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
import { decodePoolDatum, decoder, encodePoolDatum, withEncoderHex } from "./codec.ts";
import { fromHex } from "./util.ts";

// These tests run the real auto-withdrawal against an emulated ledger with the
// real pool scripts, and script the kinds of contention we see on mainnet:
// scooper spending a pool right before our submission lands, the chain indexer
// lagging behind, and transactions that get dropped or confirmed late.

const blueprint: Blueprint = decodeBlueprint(fs.readFileSync(new URL("./preview.blueprint.json", import.meta.url), "utf8"));

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

// An emulator provider whose submissions can be scripted to misbehave. Every
// accepted transaction is put in a block immediately.
class ContentionProvider extends EmulatorProvider {
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
      if (!output || output.address().getProps().paymentPart?.hash != blueprint.poolSpend.hash) {
        continue;
      }
      let datum = decodePoolDatum(decoder(fromHex(output.datum()!.asInlineData()!.toCbor())));
      datum.protocolFees += SCOOP_FEE;
      let value = new Core.Value(output.amount().coin() + SCOOP_FEE, output.amount().multiasset());
      let scooped = new TransactionOutput(output.address(), value);
      scooped.setDatum(Core.Datum.newInlineData(PlutusData.fromCbor(HexBlob(withEncoderHex(encodePoolDatum, datum)))));

      let spent = new TransactionUnspentOutput(input, output);
      this.emulator.removeUtxo(input);
      this.emulator.addUtxo(new TransactionUnspentOutput(
        new TransactionInput(TransactionId(crypto.randomBytes(32).toString("hex")), 0n),
        scooped,
      ));
      for (let [asset] of output.amount().multiasset() ?? []) {
        if (asset.startsWith(blueprint.poolSpend.hash)) {
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
  // Pool ident -> protocol fees at the start
  initialFees: Map<string, bigint>,
}

async function makeWorld(): Promise<World> {
  await Core.initCrypto();
  let skey = Core.Ed25519PrivateKey.fromNormalBytes(crypto.randomBytes(32));
  let pkh = await (await skey.toPublic()).hash();
  let wallet = Core.Address.fromBytes(HexBlob("60" + pkh.hex()));

  let emulator = new Emulator([]);
  for (let i = 0; i < 5; i++) {
    emulator.addUtxo(makeChange(wallet, 20_000_000n));
  }
  emulator.addUtxo(makeSettings(blueprint, pkh));

  // Each pool starts with 20 ADA of protocol fees
  let initialFees = new Map();
  let poolAddress;
  for (let i = 0; i < 3; i++) {
    let [pool, ident] = makeRandomPool(blueprint, pkh);
    emulator.addUtxo(pool);
    initialFees.set(ident.toString("hex"), 20_000_000n);
    poolAddress = pool.output().address();
  }

  let references = [
    makeScriptRef(wallet, HexBlob(blueprint.poolSpend.validator)),
    makeScriptRef(wallet, HexBlob(blueprint.poolManage.validator)),
  ];
  references.forEach((r) => emulator.addUtxo(r));

  // The withdrawal goes through the pool.manage stake script, which the ledger
  // requires to be registered
  let poolManageAccount = Core.RewardAccount.fromCredential({
    type: Core.CredentialType.ScriptHash,
    hash: Hash28ByteBase16(blueprint.poolManage.hash),
  }, NetworkId.Testnet);
  emulator.accounts.set(poolManageAccount, 0n);

  let provider = new ContentionProvider(emulator);
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

function runAutoWithdraw(world: World, needed: bigint, overrides: { approve?: (tx: Transaction) => Promise<boolean>, maxAttempts?: number } = {}) {
  return autoWithdrawRewards({
    poolAddress: world.poolAddress.toBech32(),
    needed,
    walletAddress: world.wallet,
    blueprint,
    stableBlueprint: undefined,
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
    stable: false,
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
