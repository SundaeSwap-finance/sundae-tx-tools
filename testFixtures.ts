// Emulated-ledger fixtures shared by the tests: a wallet, the protocol
// settings, v3 or stable pools with the real pool scripts, and a provider that
// can script the contention we see on mainnet.
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
import { EContractVersion } from "@sundaeswap/core";
import type { IPoolData as PoolData } from "@sundaeswap/core";

export const blueprint: Blueprint = decodeBlueprint(fs.readFileSync(new URL("./preview.blueprint.json", import.meta.url), "utf8"));
export const stableBlueprint: Blueprint = decodeBlueprint(fs.readFileSync(new URL("./plutus-stable-preview.json", import.meta.url), "utf8"));

// Fees that a simulated scoop adds to the pool
export const SCOOP_FEE = 2_000_000n;


export type SubmitBehavior =
  // The pool is scooped just before our transaction arrives, so it's rejected
  | "scoopFirst"
  // Accepted by the node, but never makes it into a block
  | "drop"
  // Lands on chain, but the next two confirmation checks don't see it
  | "confirmLate";

// A copy of a pool output with SCOOP_FEE more fees, as a scoop would leave it
export function scoopV3Pool(output: TransactionOutput): TransactionOutput {
  let datum = decodePoolDatum(decoder(fromHex(output.datum()!.asInlineData()!.toCbor())));
  datum.protocolFees += SCOOP_FEE;
  let value = new Core.Value(output.amount().coin() + SCOOP_FEE, output.amount().multiasset());
  let scooped = new TransactionOutput(output.address(), value);
  scooped.setDatum(Core.Datum.newInlineData(PlutusData.fromCbor(HexBlob(withEncoderHex(encodePoolDatum, datum)))));
  return scooped;
}

export function scoopStablePool(output: TransactionOutput): TransactionOutput {
  let datum = decodeStablePoolDatum(decoder(fromHex(output.datum()!.asInlineData()!.toCbor())));
  datum.protocolFees[0] += SCOOP_FEE;
  let value = new Core.Value(output.amount().coin() + SCOOP_FEE, output.amount().multiasset());
  let scooped = new TransactionOutput(output.address(), value);
  scooped.setDatum(Core.Datum.newInlineData(PlutusData.fromCbor(HexBlob(withEncoderHex(encodeStablePoolDatum, datum)))));
  return scooped;
}

// An emulator provider whose submissions can be scripted to misbehave. Every
// accepted transaction is put in a block immediately.
export class ContentionProvider extends EmulatorProvider {
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

export interface World {
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
export const STABLE_TOKEN = Core.AssetId("ab".repeat(28) + "7553444d"); // "uSDM"

// Each stable pool starts with 10 ADA of flat fees, 1 ADA of asset A (ADA)
// fees and 5 tokens of asset B fees
export const STABLE_FEES: [bigint, bigint, bigint] = [10_000_000n, 1_000_000n, 5_000_000n];

// Pool outputs must delegate to one of the authorized staking keys in the
// settings; the fixture settings authorize the wallet key
export function stablePoolAddress(stakeKeyHash: string): Core.Address {
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

export function makeStablePool(address: Core.Address, fees: [bigint, bigint, bigint]): [TransactionUnspentOutput, Buffer] {
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
export function makeV3ScriptRef(address: Core.Address, validator: string): TransactionUnspentOutput {
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
export function withMapExtensions(settings: TransactionUnspentOutput): TransactionUnspentOutput {
  let datum = decodeSettingsDatum(decoder(fromHex(settings.output().datum()!.asInlineData()!.toCbor())));
  datum.extensions = Buffer.from([0xa0]);
  let output = new TransactionOutput(settings.output().address(), settings.output().amount());
  output.setDatum(Core.Datum.newInlineData(PlutusData.fromCbor(HexBlob(withEncoderHex(encodeSettingsDatum, datum)))));
  return new TransactionUnspentOutput(settings.input(), output);
}

export async function makeWorld(kind: "v3" | "stable" = "v3", stableFees = STABLE_FEES): Promise<World> {
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

export function runAutoWithdraw(world: World, needed: bigint, overrides: { approve?: (tx: Transaction) => Promise<boolean>, maxAttempts?: number, stable?: boolean } = {}) {
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

// Order script hashes, which decodeBlueprint doesn't pick out
function orderScriptHash(blueprintFile: string): string {
  let json = JSON.parse(fs.readFileSync(new URL(blueprintFile, import.meta.url), "utf8"));
  let order = json.validators.find((v: any) => v.title.endsWith("order.spend"));
  return order.hash;
}
export const V3_ORDER_HASH = orderScriptHash("./preview.blueprint.json");
export const STABLE_ORDER_HASH = orderScriptHash("./plutus-stable-preview.json");

// Asset ids in the SDK's dotted form, with "ada.lovelace" for ada
export function sdkAssetId(asset: string): string {
  if (asset == "" || asset == "ada.lovelace") {
    return "ada.lovelace";
  }
  return `${asset.slice(0, 56)}.${asset.slice(56)}`;
}

export function makePoolData(ident: string, assetA: string, assetB: string, aReserve: bigint, bReserve: bigint, version = EContractVersion.V3): PoolData {
  return {
    ident,
    currentFee: 0.003,
    assetA: { assetId: sdkAssetId(assetA), decimals: 6 },
    assetB: { assetId: sdkAssetId(assetB), decimals: 6 },
    assetLP: { assetId: `${"cc".repeat(28)}.${ident}` },
    liquidity: { aReserve, bReserve, lpTotal: aReserve },
    version,
  };
}

// Stands in for the SundaeSwap API, serving pool data from memory. The fake
// scooper updates the reserves as it fills orders.
export class FakeQueryProvider {
  pools = new Map<string, PoolData>();

  addPool(pool: PoolData) {
    this.pools.set(pool.ident, pool);
  }

  async findPoolDataByIdent({ ident }: { ident: string }): Promise<PoolData> {
    let pool = this.pools.get(ident);
    if (!pool) {
      throw new Error(`No pool with ident ${ident}`);
    }
    return { ...pool, liquidity: { ...pool.liquidity } };
  }

  async getProtocolParamsWithScripts(version: EContractVersion) {
    let hash = version == EContractVersion.V3 ? V3_ORDER_HASH : STABLE_ORDER_HASH;
    return { blueprint: { validators: [{ title: "order.spend", hash }] } };
  }
}

// The address encoded in a Plutus Address datum
function addressFromPlutusData(data: PlutusData, network: NetworkId): Core.Address {
  let credential = (d: PlutusData) => {
    let c = d.asConstrPlutusData()!;
    return {
      type: c.getAlternative() == 0n ? Core.CredentialType.KeyHash : Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(c.getData().get(0).asBoundedBytes()!.toHex()),
    };
  };
  let [payment, stake] = [0, 1].map((i) => data.asConstrPlutusData()!.getData().get(i));
  let paymentPart = credential(payment);
  let stakeOption = stake.asConstrPlutusData()!;
  if (stakeOption.getAlternative() == 1n) {
    let type = paymentPart.type == Core.CredentialType.KeyHash ? Core.AddressType.EnterpriseKey : Core.AddressType.EnterpriseScript;
    return new Core.Address({ type, networkId: network, paymentPart });
  }
  // Some(Inline(credential))
  let inline = stakeOption.getData().get(0).asConstrPlutusData()!;
  if (inline.getAlternative() != 0n) {
    throw new Error("Pointer stake credentials aren't supported");
  }
  let delegationPart = credential(inline.getData().get(0));
  let keyPayment = paymentPart.type == Core.CredentialType.KeyHash;
  let keyStake = delegationPart.type == Core.CredentialType.KeyHash;
  let type = keyPayment
    ? (keyStake ? Core.AddressType.BasePaymentKeyStakeKey : Core.AddressType.BasePaymentKeyStakeScript)
    : (keyStake ? Core.AddressType.BasePaymentScriptStakeKey : Core.AddressType.BasePaymentScriptStakeScript);
  return new Core.Address({ type, networkId: network, paymentPart, delegationPart });
}

// A (policy, name, amount) singleton value from an order datum, as an asset id
// in the SDK's dotted form
function singletonValue(data: PlutusData): [string, bigint] {
  let items = data.asList()!;
  let policy = items.get(0).asBoundedBytes()!.toHex();
  let name = items.get(1).asBoundedBytes()!.toHex();
  return [sdkAssetId(policy + name), items.get(2).asInteger()!];
}

export interface FilledOrder {
  order: TransactionUnspentOutput,
  payout: TransactionUnspentOutput,
  offered: [string, bigint],
  received: [string, bigint],
}

// Fills swap orders the way a scooper would, against the constant product pools
// in a FakeQueryProvider. It reads everything from the order datum, so an
// order with a malformed datum makes it throw, and an order whose minimum
// can't be met is left unfilled.
export class FakeScooper {
  filled: FilledOrder[] = [];
  // Number of scoop() calls to ignore before filling anything, to mimic a
  // scooper that takes a while to get to our orders
  delayScoops = 0;
  // Protocol fee taken from each order; it must not exceed the order's max
  protocolFee = 1_000_000n;

  constructor(private emulator: Emulator, private query: FakeQueryProvider, private network = NetworkId.Testnet) {}

  scoop() {
    if (this.delayScoops > 0) {
      this.delayScoops--;
      return;
    }
    for (let utxo of this.emulator.utxos()) {
      let hash = utxo.output().address().getProps().paymentPart?.hash;
      if (hash == V3_ORDER_HASH || hash == STABLE_ORDER_HASH) {
        this.fill(utxo, hash == V3_ORDER_HASH ? EContractVersion.V3 : EContractVersion.Stableswaps);
      }
    }
  }

  private fill(order: TransactionUnspentOutput, version: EContractVersion) {
    let fields = order.output().datum()!.asInlineData()!.asConstrPlutusData()!.getData();
    let identOption = fields.get(0).asConstrPlutusData()!;
    if (identOption.getAlternative() != 0n) {
      throw new Error("Orders without a pool ident aren't supported");
    }
    let ident = identOption.getData().get(0).asBoundedBytes()!.toHex();
    let maxFee = fields.get(2).asInteger()!;
    let destination = fields.get(3).asConstrPlutusData()!;
    if (destination.getAlternative() != 0n) {
      throw new Error("Only fixed destinations are supported");
    }
    let destinationAddress = addressFromPlutusData(destination.getData().get(0), this.network);
    let destinationDatum = destination.getData().get(1).asConstrPlutusData()!;
    let details = fields.get(4).asConstrPlutusData()!;
    if (details.getAlternative() != 1n) {
      throw new Error("Only swap orders are supported");
    }
    let [offerAsset, offerAmount] = singletonValue(details.getData().get(0));
    let [minAsset, minAmount] = singletonValue(details.getData().get(1));

    let pool = this.query.pools.get(ident);
    if (!pool) {
      throw new Error(`Order for unknown pool ${ident}`);
    }
    if (pool.version != version) {
      throw new Error(`Order for ${pool.version} pool ${ident} was placed at the ${version} order script`);
    }
    if (this.protocolFee > maxFee) {
      return;
    }
    let aToB = offerAsset == pool.assetA.assetId;
    if (!aToB && offerAsset != pool.assetB.assetId) {
      throw new Error(`Order offers ${offerAsset}, which pool ${ident} doesn't trade`);
    }
    let receivedAsset = aToB ? pool.assetB.assetId : pool.assetA.assetId;
    if (minAsset != receivedAsset) {
      throw new Error(`Order wants ${minAsset} from pool ${ident}, which pays ${receivedAsset}`);
    }
    let [reserveIn, reserveOut] = aToB
      ? [pool.liquidity.aReserve, pool.liquidity.bReserve]
      : [pool.liquidity.bReserve, pool.liquidity.aReserve];
    let feeBps = BigInt(Math.round(pool.currentFee * 10_000));
    let received = reserveOut * offerAmount * (10_000n - feeBps) / (reserveIn * 10_000n + offerAmount * (10_000n - feeBps));
    if (received < minAmount) {
      return;
    }
    if (aToB) {
      pool.liquidity.aReserve += offerAmount;
      pool.liquidity.bReserve -= received;
    } else {
      pool.liquidity.bReserve += offerAmount;
      pool.liquidity.aReserve -= received;
    }

    // The payout is the order's value, less the protocol fee and what was
    // offered, plus what was received
    let payoutAssets = new Map(order.output().amount().multiasset() ?? []);
    let coin = order.output().amount().coin() - this.protocolFee;
    let adjust = (asset: string, delta: bigint) => {
      if (asset == "ada.lovelace") {
        coin += delta;
      } else {
        let id = Core.AssetId(asset.replace(".", ""));
        let quantity = (payoutAssets.get(id) ?? 0n) + delta;
        if (quantity < 0n) {
          throw new Error(`Order doesn't hold the ${-delta} ${asset} it offers`);
        }
        if (quantity == 0n) {
          payoutAssets.delete(id);
        } else {
          payoutAssets.set(id, quantity);
        }
      }
    };
    adjust(offerAsset, -offerAmount);
    adjust(receivedAsset, received);
    let payoutOutput = new TransactionOutput(destinationAddress, new Core.Value(coin, payoutAssets.size > 0 ? payoutAssets : undefined));
    // NoDatum = 0, DatumHash = 1, InlineDatum = 2
    if (destinationDatum.getAlternative() == 2n) {
      payoutOutput.setDatum(Core.Datum.newInlineData(destinationDatum.getData().get(0)));
    } else if (destinationDatum.getAlternative() != 0n) {
      throw new Error("Datum hash destinations aren't supported");
    }

    let payout = new TransactionUnspentOutput(
      new TransactionInput(TransactionId(crypto.randomBytes(32).toString("hex")), 0n),
      payoutOutput,
    );
    this.emulator.removeUtxo(order.input());
    this.emulator.addUtxo(payout);
    this.filled.push({ order, payout, offered: [offerAsset, offerAmount], received: [receivedAsset, received] });
  }
}
