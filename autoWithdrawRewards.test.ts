import { describe, it, expect, beforeEach } from "bun:test";
import * as fs from "node:fs";
import * as crypto from "node:crypto";
import {
  Ed25519PrivateNormalKeyHex,
  Hash28ByteBase16,
  HexBlob,
  NetworkId,
  PlutusData,
  Transaction,
  TransactionId,
  TransactionInput,
  TransactionOutput,
  TransactionUnspentOutput,
} from "@blaze-cardano/core";
import { Blaze, Core, HotSingleWallet } from "@blaze-cardano/sdk";
import { Emulator, EmulatorProvider } from "@blaze-cardano/emulator";
import {
  autoWithdrawRewards,
  decodeBlueprint,
  makeChange,
  makeRandomPool,
  makeScriptRef,
  makeSettings,
  submitAndAwaitWithRetry,
  type Blueprint,
} from "./index.ts";
import {
  decodePoolDatum,
  decodeSettingsDatum,
  decodeStablePoolDatum,
  decoder,
  encodePoolDatum,
  encodeSettingsDatum,
  encodeStablePoolDatum,
  withEncoderHex,
} from "./codec.ts";
import { fromHex } from "./util.ts";

// These tests run the real auto-withdrawal against an emulated ledger with the
// real pool scripts, and script the kinds of contention we see on mainnet:
// scooper spending a pool right before our submission lands, the chain indexer
// lagging behind, and transactions that get dropped or confirmed late.

const blueprint: Blueprint = decodeBlueprint(fs.readFileSync(new URL("./preview.blueprint.json", import.meta.url), "utf8"));
const stableBlueprint: Blueprint = decodeBlueprint(fs.readFileSync(new URL("./plutus-stable-preview.json", import.meta.url), "utf8"));

// Fees that a simulated scoop adds to the pool
const SCOOP_FEE = 2_000_000n;

// Each fixture pool has 17 ADA withdrawable (20 ADA of fees less 3 ADA left
// behind), so this takes all of two pools and part of the third. The partial
// withdrawal still withholds more than min-ADA; below that, the builder tops
// up the withheld output from change.
const NEEDED = 44_000_000n;

type SubmitBehavior =
  // The pool is scooped just before our transaction arrives, so it's rejected
  | "scoopFirst"
  // Accepted by the node, but never makes it into a block
  | "drop"
  // Lands on chain, but the next two confirmation checks don't see it
  | "confirmLate";

// A copy of a pool output with SCOOP_FEE more fees, as a scoop would leave it
function scoopV3Pool(output: TransactionOutput): TransactionOutput {
  let datum = decodePoolDatum(decoder(fromHex(output.datum()!.asInlineData()!.toCbor())));
  datum.protocolFees += SCOOP_FEE;
  let value = new Core.Value(output.amount().coin() + SCOOP_FEE, output.amount().multiasset());
  let scooped = new TransactionOutput(output.address(), value);
  scooped.setDatum(Core.Datum.newInlineData(PlutusData.fromCbor(HexBlob(withEncoderHex(encodePoolDatum, datum)))));
  return scooped;
}

function scoopStablePool(output: TransactionOutput): TransactionOutput {
  let datum = decodeStablePoolDatum(decoder(fromHex(output.datum()!.asInlineData()!.toCbor())));
  datum.protocolFees[0] += SCOOP_FEE;
  let value = new Core.Value(output.amount().coin() + SCOOP_FEE, output.amount().multiasset());
  let scooped = new TransactionOutput(output.address(), value);
  scooped.setDatum(Core.Datum.newInlineData(PlutusData.fromCbor(HexBlob(withEncoderHex(encodeStablePoolDatum, datum)))));
  return scooped;
}

// An emulator provider whose submissions can be scripted to misbehave. Every
// accepted transaction is put in a block immediately.
class ContentionProvider extends EmulatorProvider {
  constructor(emulator: Emulator, private poolScriptHash: string, private scoopPool: (output: TransactionOutput) => TransactionOutput) {
    super(emulator);
  }

  // Behaviors for upcoming submissions, consumed in order. Submissions beyond
  // the script behave normally.
  script: (SubmitBehavior | "normal")[] = [];
  // How many times getUnspentOutputByNFT should still return a pool utxo that a
  // scoop already spent, to mimic indexer lag
  staleReadsAfterScoop = 0;
  submissions: Transaction[] = [];
  landed = new Set<string>();
  private hiddenChecks = new Map<string, number>();
  private stale = new Map<string, { utxo: TransactionUnspentOutput, remaining: number }>();

  async postTransactionToChain(tx: Transaction): Promise<TransactionId> {
    this.submissions.push(tx);
    let behavior = this.script.shift() ?? "normal";
    if (behavior == "scoopFirst") {
      this.scoopPoolsSpentBy(tx);
    }
    if (behavior == "drop") {
      return tx.getId();
    }
    let id = await super.postTransactionToChain(tx);
    this.emulator.stepForwardBlock();
    this.landed.add(id);
    if (behavior == "confirmLate") {
      this.hiddenChecks.set(id, 2);
    }
    return id;
  }

  async awaitTransactionConfirmation(txId: TransactionId, _timeout?: number): Promise<boolean> {
    let hidden = this.hiddenChecks.get(txId) ?? 0;
    if (hidden > 0) {
      this.hiddenChecks.set(txId, hidden - 1);
      return false;
    }
    return this.landed.has(txId);
  }

  async getUnspentOutputByNFT(unit: Core.AssetId): Promise<TransactionUnspentOutput> {
    let stale = this.stale.get(unit);
    if (stale && stale.remaining > 0) {
      stale.remaining--;
      return stale.utxo;
    }
    return super.getUnspentOutputByNFT(unit);
  }

  // Replace each pool that the transaction spends with a new utxo holding more
  // fees, as if a scooper got there first
  scoopPoolsSpentBy(tx: Transaction) {
    for (let input of tx.body().inputs().values()) {
      let output = this.emulator.getOutput(input);
      if (!output || output.address().getProps().paymentPart?.hash != this.poolScriptHash) {
        continue;
      }
      let spent = new TransactionUnspentOutput(input, output);
      this.emulator.removeUtxo(input);
      this.emulator.addUtxo(new TransactionUnspentOutput(
        new TransactionInput(TransactionId(crypto.randomBytes(32).toString("hex")), 0n),
        this.scoopPool(output),
      ));
      for (let [asset] of output.amount().multiasset() ?? []) {
        if (asset.startsWith(this.poolScriptHash)) {
          this.stale.set(asset, { utxo: spent, remaining: this.staleReadsAfterScoop });
        }
      }
    }
  }
}

interface World {
  emulator: Emulator,
  provider: ContentionProvider,
  blaze: Blaze<ContentionProvider, HotSingleWallet>,
  wallet: Core.Address,
  signer: string,
  poolAddress: Core.Address,
  references: TransactionInput[],
  // Pool ident -> protocol fees at the start (v3 pools only)
  initialFees: Map<string, bigint>,
}

// Stable pools trade ADA against this token
const STABLE_TOKEN = Core.AssetId("ab".repeat(28) + "7553444d"); // "uSDM"

// Each stable pool starts with 10 ADA of flat fees, 1 ADA of asset A (ADA)
// fees and 5 tokens of asset B fees
const STABLE_FEES: [bigint, bigint, bigint] = [10_000_000n, 1_000_000n, 5_000_000n];

// Pool outputs must delegate to one of the authorized staking keys in the
// settings; the fixture settings authorize the wallet key
function stablePoolAddress(stakeKeyHash: string): Core.Address {
  return new Core.Address({
    type: Core.AddressType.BasePaymentScriptStakeKey,
    networkId: NetworkId.Testnet,
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(stableBlueprint.poolSpend.hash),
    },
    delegationPart: {
      type: Core.CredentialType.KeyHash,
      hash: Hash28ByteBase16(stakeKeyHash),
    },
  });
}

function makeStablePool(address: Core.Address, fees: [bigint, bigint, bigint]): [TransactionUnspentOutput, Buffer] {
  let identifier = crypto.randomBytes(28);
  let [policy, name] = [STABLE_TOKEN.slice(0, 56), STABLE_TOKEN.slice(56)];
  let datum = withEncoderHex(encodeStablePoolDatum, {
    identifier,
    assetPair: [
      [Buffer.alloc(0), Buffer.alloc(0)],
      [fromHex(policy), fromHex(name)],
    ],
    circulatingLp: 100_000_000n,
    lpFeeBasisPoints: [5n, 5n],
    protocolFeeBasisPoints: [5n, 5n],
    feeManager: null,
    marketOpen: 0n,
    protocolFees: fees,
    linearAmplification: 200n,
    sumInvariant: 200_000_000n,
    linearAmplificationManager: null,
  });
  let nft = Core.AssetId(stableBlueprint.poolSpend.hash + "000de140" + identifier.toString("hex"));
  // 100 ADA and 100 tokens of liquidity, plus the fees
  let output = new TransactionOutput(address, new Core.Value(
    100_000_000n + fees[0] + fees[1],
    new Map([[STABLE_TOKEN, 100_000_000n + fees[2]], [nft, 1n]]),
  ));
  output.setDatum(Core.Datum.newInlineData(PlutusData.fromCbor(HexBlob(datum))));
  let input = new TransactionInput(TransactionId(crypto.randomBytes(32).toString("hex")), 0n);
  return [new TransactionUnspentOutput(input, output), identifier];
}

// Like makeScriptRef, but for the PlutusV3 stable scripts
function makeV3ScriptRef(address: Core.Address, validator: string): TransactionUnspentOutput {
  let output = new TransactionOutput(address, new Core.Value(100_000_000n));
  output.setScriptRef(Core.Script.newPlutusV3Script(new Core.PlutusV3Script(HexBlob(validator))));
  // The stable scripts expect the settings to be the first reference input, and
  // makeSettings gives it a tx id starting with 00, so sort these after it
  let txId = "ff" + crypto.randomBytes(31).toString("hex");
  let input = new TransactionInput(TransactionId(txId), 0n);
  return new TransactionUnspentOutput(input, output);
}

// makeSettings encodes the extensions field as Void, but the live settings were
// migrated to an empty map (see updateSettingsDatum), and the stable scripts
// require one
function withMapExtensions(settings: TransactionUnspentOutput): TransactionUnspentOutput {
  let datum = decodeSettingsDatum(decoder(fromHex(settings.output().datum()!.asInlineData()!.toCbor())));
  datum.extensions = Buffer.from([0xa0]);
  let output = new TransactionOutput(settings.output().address(), settings.output().amount());
  output.setDatum(Core.Datum.newInlineData(PlutusData.fromCbor(HexBlob(withEncoderHex(encodeSettingsDatum, datum)))));
  return new TransactionUnspentOutput(settings.input(), output);
}

async function makeWorld(kind: "v3" | "stable" = "v3", stableFees = STABLE_FEES): Promise<World> {
  await Core.initCrypto();
  let skey = Core.Ed25519PrivateKey.fromNormalBytes(crypto.randomBytes(32));
  let pkh = await (await skey.toPublic()).hash();
  let wallet = Core.Address.fromBytes(HexBlob("60" + pkh.hex()));

  let emulator = new Emulator([]);
  for (let i = 0; i < 5; i++) {
    emulator.addUtxo(makeChange(wallet, 20_000_000n));
  }
  // Stable pools use the v3 settings
  emulator.addUtxo(withMapExtensions(makeSettings(blueprint, pkh)));

  let initialFees = new Map();
  let poolAddress;
  let references;
  let poolBlueprint;
  if (kind == "v3") {
    // Each pool starts with 20 ADA of protocol fees
    for (let i = 0; i < 3; i++) {
      let [pool, ident] = makeRandomPool(blueprint, pkh);
      emulator.addUtxo(pool);
      initialFees.set(ident.toString("hex"), 20_000_000n);
      poolAddress = pool.output().address();
    }
    references = [
      makeScriptRef(wallet, HexBlob(blueprint.poolSpend.validator)),
      makeScriptRef(wallet, HexBlob(blueprint.poolManage.validator)),
    ];
    poolBlueprint = blueprint;
  } else {
    for (let i = 0; i < 2; i++) {
      emulator.addUtxo(makeStablePool(stablePoolAddress(pkh.hex()), stableFees)[0]);
    }
    poolAddress = stablePoolAddress(pkh.hex());
    references = [
      makeV3ScriptRef(wallet, stableBlueprint.poolSpend.validator),
      makeV3ScriptRef(wallet, stableBlueprint.poolManage.validator),
    ];
    poolBlueprint = stableBlueprint;
  }
  references.forEach((r) => emulator.addUtxo(r));

  // The withdrawal goes through the pool.manage stake script, which the ledger
  // requires to be registered
  let poolManageAccount = Core.RewardAccount.fromCredential({
    type: Core.CredentialType.ScriptHash,
    hash: Hash28ByteBase16(poolBlueprint.poolManage.hash),
  }, NetworkId.Testnet);
  emulator.accounts.set(poolManageAccount, 0n);

  let provider = new ContentionProvider(emulator, poolBlueprint.poolSpend.hash, kind == "v3" ? scoopV3Pool : scoopStablePool);
  let blaze = await Blaze.from(provider, new HotSingleWallet(Ed25519PrivateNormalKeyHex(skey.hex()), NetworkId.Testnet, provider));

  return {
    emulator,
    provider,
    blaze,
    wallet,
    signer: pkh.hex(),
    poolAddress: poolAddress!,
    references: references.map((r) => r.input()),
    initialFees,
  };
}

function runAutoWithdraw(world: World, needed: bigint, overrides: { approve?: (tx: Transaction) => Promise<boolean>, maxAttempts?: number, stable?: boolean } = {}) {
  return autoWithdrawRewards({
    poolAddress: world.poolAddress.toBech32(),
    needed,
    walletAddress: world.wallet,
    blueprint,
    stableBlueprint: overrides.stable ? stableBlueprint : undefined,
    blaze: world.blaze,
    provider: world.provider,
    references: world.references,
    retry: {
      approve: overrides.approve ?? (async () => true),
      maxAttempts: overrides.maxAttempts ?? 10,
      retryDelayMs: 0,
      confirmationTimeoutMs: 0,
    },
    withheldAddress: world.wallet,
    signers: world.signer,
    txLogDir: "",
    todo: undefined,
    stable: overrides.stable ?? false,
  });
}

// Pool ident -> protocol fees currently on the ledger
function currentFees(world: World): Map<string, bigint> {
  let fees = new Map();
  for (let utxo of world.emulator.utxos()) {
    if (utxo.output().address().toBytes() != world.poolAddress.toBytes()) {
      continue;
    }
    let datum = decodePoolDatum(decoder(fromHex(utxo.output().datum()!.asInlineData()!.toCbor())));
    fees.set(datum.identifier.toString("hex"), datum.protocolFees);
  }
  return fees;
}

// Pool ident -> how much was withdrawn from it, after accounting for fees that
// simulated scoops added
function withdrawnPerPool(world: World, scoopsPerPool: Map<string, number> = new Map()): Map<string, bigint> {
  let withdrawn = new Map();
  for (let [ident, fees] of currentFees(world)) {
    let added = BigInt(scoopsPerPool.get(ident) ?? 0) * SCOOP_FEE;
    withdrawn.set(ident, world.initialFees.get(ident)! + added - fees);
  }
  return withdrawn;
}

function sum(values: Iterable<bigint>): bigint {
  let total = 0n;
  for (let v of values) {
    total += v;
  }
  return total;
}

function coins(utxos: TransactionUnspentOutput[]): bigint {
  return sum(utxos.map((u) => u.output().amount().coin()));
}

// The withheld share of a withdrawal under the fixture settings' 1/10 treasury
// allowance; see buildWithdrawPoolRewards
function withheldShare(withdrawn: bigint): bigint {
  let treasury = 9n * withdrawn / 10n + 1n;
  if (treasury < 1_000_000n) {
    treasury = 1_000_000n;
  }
  return withdrawn - treasury;
}

// Each scooped pool, keyed by ident, with how many times it was scooped
function scoopCounts(world: World, txs: Transaction[]): Map<string, number> {
  let counts = new Map();
  for (let tx of txs) {
    let datum = decodePoolDatum(decoder(fromHex(tx.body().outputs()[0].datum()!.asInlineData()!.toCbor())));
    let ident = datum.identifier.toString("hex");
    counts.set(ident, (counts.get(ident) ?? 0) + 1);
  }
  return counts;
}

describe("autoWithdrawRewards", () => {
  let world: World;

  beforeEach(async () => {
    world = await makeWorld();
  });

  it("withdraws the needed amount across pools, largest first", async () => {
    let { rewards } = await runAutoWithdraw(world, NEEDED);

    let withdrawn = withdrawnPerPool(world);
    expect([...withdrawn.values()].sort()).toEqual([17_000_000n, 17_000_000n, 10_000_000n].sort());
    expect(world.provider.submissions.length).toBe(3);
    expect(coins(rewards)).toBe(sum([...withdrawn.values()].map(withheldShare)));
  });

  it("retries a withdrawal whose pool was scooped first", async () => {
    world.provider.script = ["normal", "scoopFirst"];
    let { rewards } = await runAutoWithdraw(world, NEEDED);

    // The second submission was rejected and rebuilt against the scooped pool
    expect(world.provider.submissions.length).toBe(4);
    let scooped = scoopCounts(world, [world.provider.submissions[1]]);
    let withdrawn = withdrawnPerPool(world, scooped);
    expect(sum(withdrawn.values())).toBe(NEEDED);
    expect(coins(rewards)).toBe(sum([...withdrawn.values()].map(withheldShare)));
  });

  it("keeps retrying while the indexer still serves the spent pool", async () => {
    world.provider.script = ["scoopFirst"];
    world.provider.staleReadsAfterScoop = 2;
    await runAutoWithdraw(world, NEEDED);

    // Two more rejected attempts against the stale pool, then success
    expect(world.provider.submissions.length).toBe(6);
    let scooped = scoopCounts(world, [world.provider.submissions[0]]);
    expect(sum(withdrawnPerPool(world, scooped).values())).toBe(NEEDED);
  });

  it("resubmits a withdrawal that was accepted but dropped", async () => {
    world.provider.script = ["drop"];
    let { rewards } = await runAutoWithdraw(world, NEEDED);

    expect(world.provider.submissions.length).toBe(4);
    let withdrawn = withdrawnPerPool(world);
    expect(sum(withdrawn.values())).toBe(NEEDED);
    // The dropped transaction's outputs aren't reported as rewards
    expect(coins(rewards)).toBe(sum([...withdrawn.values()].map(withheldShare)));
  });

  it("doesn't withdraw twice when a confirmation arrives late", async () => {
    world.provider.script = ["confirmLate"];
    let { rewards } = await runAutoWithdraw(world, NEEDED);

    // While the landed attempt is still hidden, the retry finds the pool at the
    // landed attempt's output and tries to withdraw again, but it spends the
    // same change as the landed attempt, so it can never land. Then the landed
    // attempt is found.
    expect(world.provider.landed.size).toBe(3);
    let withdrawn = withdrawnPerPool(world);
    expect([...withdrawn.values()].sort()).toEqual([17_000_000n, 17_000_000n, 10_000_000n].sort());
    expect(rewards.map((r) => r.input().transactionId())).toContain(world.provider.submissions[0].getId());
    expect(coins(rewards)).toBe(sum([...withdrawn.values()].map(withheldShare)));
  });

  it("gives up after the maximum number of attempts", async () => {
    world.provider.script = ["scoopFirst", "scoopFirst", "scoopFirst"];
    await expect(runAutoWithdraw(world, NEEDED, { maxAttempts: 3 })).rejects.toThrow(/Gave up after 3 attempts/);
  });

  it("stops when the operator declines", async () => {
    await expect(runAutoWithdraw(world, NEEDED, { approve: async () => false })).rejects.toThrow(/Aborted by operator/);
    expect(world.provider.submissions.length).toBe(0);
  });

  it("reports no rewards when the whole withdrawal goes to the treasury", async () => {
    // The treasury takes at least 1 ADA, so nothing is withheld
    let { rewards, change } = await runAutoWithdraw(world, 1_000_000n);

    expect(sum(withdrawnPerPool(world).values())).toBe(1_000_000n);
    expect(rewards).toEqual([]);
    expect(change.length).toBe(1);
  });
});

// Pool ident -> [flat, asset A, asset B] protocol fees currently on the ledger
function currentStableFees(world: World): Map<string, [bigint, bigint, bigint]> {
  let fees = new Map();
  for (let utxo of world.emulator.utxos()) {
    if (utxo.output().address().toBytes() != world.poolAddress.toBytes()) {
      continue;
    }
    let datum = decodeStablePoolDatum(decoder(fromHex(utxo.output().datum()!.asInlineData()!.toCbor())));
    fees.set(datum.identifier.toString("hex"), datum.protocolFees);
  }
  return fees;
}

describe("autoWithdrawRewards on stable pools", () => {
  let world: World;

  beforeEach(async () => {
    world = await makeWorld("stable");
  });

  // Everything but 3 ADA of flat fees is withdrawn. The fixture settings allow
  // us to withhold 1/10 of each part, rounded down as the pool.manage script
  // does, and the treasury gets the rest.
  function withheld(fees: [bigint, bigint, bigint]): { ada: bigint, tokens: bigint } {
    return {
      ada: (fees[0] - 3_000_000n) / 10n + fees[1] / 10n,
      tokens: fees[2] / 10n,
    };
  }

  function expectRewards(rewards: TransactionUnspentOutput[], fees = STABLE_FEES) {
    expect(rewards.length).toBe(2);
    for (let reward of rewards) {
      expect(reward.output().amount().multiasset()?.get(STABLE_TOKEN)).toBe(withheld(fees).tokens);
      // The builder tops this output up to min-ADA from change, so it can hold
      // more ADA than was withheld
      expect(reward.output().amount().coin()).toBeGreaterThanOrEqual(withheld(fees).ada);
    }
  }

  it("pays the treasury its rounded-up share when fees don't divide evenly", async () => {
    let fees: [bigint, bigint, bigint] = [10_000_007n, 1_000_003n, 5_000_009n];
    world = await makeWorld("stable", fees);
    let { rewards } = await runAutoWithdraw(world, 0n, { stable: true });

    expect(world.provider.submissions.length).toBe(2);
    for (let tx of world.provider.submissions) {
      let treasury = tx.body().outputs()[1].amount();
      expect(treasury.coin()).toBe(fees[0] - 3_000_000n + fees[1] - withheld(fees).ada);
      expect(treasury.multiasset()?.get(STABLE_TOKEN)).toBe(fees[2] - withheld(fees).tokens);
    }
    expectRewards(rewards, fees);
  });

  it("withdraws all fees but the flat 3 ADA from every pool", async () => {
    let { rewards } = await runAutoWithdraw(world, 0n, { stable: true });

    expect(world.provider.submissions.length).toBe(2);
    for (let fees of currentStableFees(world).values()) {
      expect(fees).toEqual([3_000_000n, 0n, 0n]);
    }
    expectRewards(rewards);
  });

  it("retries a withdrawal whose pool was scooped first", async () => {
    world.provider.script = ["scoopFirst"];
    world.provider.staleReadsAfterScoop = 1;
    let { rewards } = await runAutoWithdraw(world, 0n, { stable: true });

    // One rejection after the scoop, one against the stale pool, then success
    expect(world.provider.submissions.length).toBe(4);
    // The amounts were fixed before the scoop, so the scoop's fees stay behind
    let remaining = [...currentStableFees(world).values()].map((f) => f[0]).sort();
    expect(remaining).toEqual([3_000_000n, 3_000_000n + SCOOP_FEE].sort());
    for (let fees of currentStableFees(world).values()) {
      expect(fees.slice(1)).toEqual([0n, 0n]);
    }
    expectRewards(rewards);
  });
});

describe("submitAndAwaitWithRetry", () => {
  it("refuses a retry that doesn't spend the anchor input", async () => {
    let world = await makeWorld();
    world.provider.script = ["drop"];
    let change = (await world.provider.getUnspentOutputs(world.wallet)).filter((u) => !u.output().scriptRef());

    // A builder that picks fresh change on every attempt, so a late landing
    // first attempt and a retry could both land
    let attempt = 0;
    let buildTx = async () => {
      let tx = await world.blaze
        .newTransaction()
        .addInput(change[attempt++])
        .payLovelace(world.wallet, 5_000_000n)
        .complete({ useCoinSelection: false });
      return tx;
    };

    let retry = { approve: async () => true, maxAttempts: 10, retryDelayMs: 0, confirmationTimeoutMs: 0 };
    await expect(submitAndAwaitWithRetry(world.blaze, retry, change[0].input(), buildTx)).rejects.toThrow(/doesn't spend the anchor input/);
    // Only the first, dropped attempt was submitted
    expect(world.provider.submissions.length).toBe(1);
  });
});
