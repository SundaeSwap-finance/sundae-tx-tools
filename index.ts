import * as rl from "node:readline/promises";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import { mkdir } from "node:fs/promises";
import * as readline from "node:readline/promises";
import { stdin, stdout } from "node:process";
import {
  Address,
  CborSet,
  Datum,
  DatumKind,
  Ed25519PrivateNormalKeyHex,
  Ed25519PrivateKey,
  Hash28ByteBase16,
  Hash32ByteBase16,
  HexBlob,
  NetworkId,
  PlutusData,
  PlutusV2Script,
  PlutusV3Script,
  Script,
  Transaction,
  TransactionId,
  TransactionInput,
  TransactionOutput,
  TransactionWitnessSet,
  Value,
  VkeyWitness,
  signMessage as blazeSignMessage,
} from "@blaze-cardano/core";
import { ColdWallet, HotSingleWallet, Core, Blaze, Blockfrost, Provider, Wallet } from "@blaze-cardano/sdk";
import { TxBuilder } from "@blaze-cardano/tx";
import { Emulator, EmulatorProvider } from "@blaze-cardano/emulator";
import { Ed25519KeyHash } from "@cardano-sdk/crypto";
import * as ed from "@noble/ed25519";
import {
  decoder,
  decodeNewFees,
  decodeNewFeeManager,
  decodePoolDatum,
  decodeSettingsDatum,
  decodeStablePoolDatum,
  encoder,
  withEncoder,
  withEncoderHex,
  encodePoolDatum,
  encodePoolSpendRedeemer,
  encodePoolManageRedeemer,
  encodeConvenienceFeeManagerRedeemer,
  encodeNewFees,
  encodeNewFeeManager,
  encodeSettingsDatum,
  encodeStablePoolDatum,
  encodeStablePoolManageRedeemer,
  encodeStablePoolSpendRedeemer,
  assetClassIsAda,
  assetClassToAssetId,
  newAddress,
  MultisigSignature,
  Address as CodecAddress,
  NewFees,
  NewFeeManager,
  ConvenienceFeeManagerRedeemerUpdateFee,
  ConvenienceFeeManagerRedeemerUpdateFeeManager,
  PoolDatum,
  StablePoolDatum,
  SettingsDatum,
  AssetPair,
} from "./codec.ts";
import {
  fromHex,
  stringify,
} from "./util.ts";

import minimist from "minimist";

import { EContractVersion, EDatumType, EContractVersion, QueryProviderSundaeSwap, SundaeSDK, DatumBuilderV3, SwapConfig, ESwapType } from "@sundaeswap/core";
import { AssetAmount } from "@sundaeswap/asset";

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function valueIsZero(v: Value) {
  let coreValue = v.toCore();
  if (coreValue.assets) {
    for (let [assetId, amount] of coreValue.assets) {
      if (amount != 0n) {
        return false;
      }
    }
  }
  return coreValue.coins == 0n;
}

async function queryRewards(mainnet: boolean, stakeAddress: string): Promise<bigint | undefined> {
  const projectId = process.env["BLOCKFROST_PROJECT_ID"];
  let queryString = "";
  if (mainnet) {
    queryString = "https://cardano-mainnet.blockfrost.io/api/v0/accounts/"
  } else {
    queryString = "https://cardano-preview.blockfrost.io/api/v0/accounts/"
  }
  queryString += stakeAddress;
  const response = await fetch(queryString, {
    headers: { "project_id": projectId }, 
  });
  try {
    let amount = BigInt((await response.json())["withdrawable_amount"]);
    return amount;
  } catch (e) {
    return undefined;
  }
}

async function prompt(s: string): Promise<string> {
  const rl = readline.createInterface({ input: stdin, output: stdout });
  let answer = await rl.question(s + ' ');
  rl.close();
  return answer;
}

function envelope(txBytes: string) {
  return `{
  "type": "Witnessed Tx ConwayEra",
  "description": "Ledger Cddl Format",
  "cborHex": "${txBytes}"
}`;
}

function hexEncode(s: string): string {
  return Buffer.from(s, "utf8").toString("hex");
}

function hexEncodeBuffer(b: Buffer): string {
  return b.toString("hex");
}

async function findSettings(provider: Provider, settingsAddress: Address, settingsPolicyId: string): Promise<Core.TransactionUnspentOutput> {
  let settingsUtxos: Core.TransactionUnspentOutput[] = await provider.getUnspentOutputs(settingsAddress);
  for (let settingsUtxo of settingsUtxos) {
    let assetId = Core.AssetId(settingsPolicyId + hexEncode("settings"));
    let ma = settingsUtxo.output().amount().multiasset();
    if (ma == undefined) {
      continue;
    }
    if (ma.get(assetId) == 1n) {
      return settingsUtxo;
    }
  }
  throw new Error("findSettings: Couldn't find a UTxO with the settings NFT at the settings address.");
}

async function findPoolByIdent(provider: Provider, poolAddress: Core.Address, poolIdent: string): Promise<Core.TransactionUnspentOutput> {
  let pool = null;
  // the pool policy is the same as the spending validator hash
  let poolPolicy = poolAddress.getProps().paymentPart?.hash;
  if (!poolPolicy) {
    throw new Error("Couldn't get pool policy");
  }
  let poolNft = poolPolicy + "000de140" + poolIdent;
  let poolNftAssetId = Core.AssetId(poolNft);
  let knownPool = await provider.getUnspentOutputByNFT(poolNftAssetId);
  if (knownPool) {
    let datum = knownPool.output().datum();
    if (!datum) {
      throw new Error("invalid datum");
    }
    let datumCbor = (datum.toCore() as any).cbor;
    let pd = decodePoolDatum(decoder(fromHex(datumCbor)));
    //console.log(pd.identifier.toString('hex'));
    if (pd.identifier.toString('hex') == poolIdent) {
      //console.log("found pool");
      pool = knownPool;
    }
  }
  if (!pool) {
    throw new Error(`Couldn't find pool with ident: ${poolIdent}`);
  }
  return pool;
}

export async function findStablePoolByIdent(provider: Provider, poolAddress: Core.Address, poolIdent: string): Promise<Core.TransactionUnspentOutput> {
  let pool = null;
  let poolPolicy = poolAddress.getProps().paymentPart?.hash;
  if (!poolPolicy) {
    throw new Error("Couldn't get pool policy");
  }
  let poolNft = poolPolicy + "000de140" + poolIdent;
  let poolNftAssetId = Core.AssetId(poolNft);
  let knownPool = await provider.getUnspentOutputByNFT(poolNftAssetId);
  if (knownPool) {
    let datum = knownPool.output().datum();
    if (!datum) {
      throw new Error("invalid datum");
    }
    let datumInline = datum.asInlineData();
    if (!datumInline) {
      throw new Error("expected inline datum on stable pool");
    }
    let datumCbor = datumInline.toCbor();
    let pd = decodeStablePoolDatum(decoder(fromHex(datumCbor)));
    if (pd.identifier.toString('hex') == poolIdent) {
      pool = knownPool;
    }
  }
  if (!pool) {
    throw new Error(`Couldn't find stable pool with ident: ${poolIdent}`);
  }
  return pool;
}

// Find a change utxo in the wallet having at least the given amount
async function findChange(provider: Provider, address: Core.Address, amount: bigint): Promise<Core.TransactionUnspentOutput> {
  const utxos: Core.TransactionUnspentOutput[] = await provider.getUnspentOutputs(address);
  for (const utxo of utxos) {
    // Skip utxos with assets
    let ma = utxo.output().amount().multiasset();
    if (ma != undefined && ma.size > 0) {
      continue;
    }
    // Skip utxos with scripts
    if (utxo.output().scriptRef()) {
      continue;
    }
    // Skip utxos with datums
    if (utxo.output().datum()) {
      continue;
    }
    if (utxo.output().amount().coin() >= amount) {
      return utxo;
    }
  }
  throw new Error(`Couldn't find a change utxo with ${amount} lovelace`);
}

// Collect many change utxos each having a minimum amount
async function findChangeMany(provider: Provider, address: Core.Address, amount: bigint, count: bigint): Promise<Core.TransactionUnspentOutput[]> {
  const utxos = await provider.getUnspentOutputs(address);
  let change = [];
  for (const utxo of utxos) {
    // Skip utxos with assets
    let ma = utxo.output().amount().multiasset();
    if (ma != undefined && ma.size > 0) {
      continue;
    }
    // Skip utxos with scripts
    if (utxo.output().scriptRef()) {
      continue;
    }
    // Skip utxos with datums
    if (utxo.output().datum()) {
      continue;
    }
    if (utxo.output().amount().coin() >= amount) {
      change.push(utxo);
      if (change.length >= count) {
        break;
      }
    }
  }
  if (change.length < count) {
    throw new Error(`Couldn't find enough change utxos: ${change.length}/${count}`);
  }
  return change;
}

class Multiasset {
  ma: Map<string, bigint>;
  
  public constructor() {
    this.ma = new Map();
  }

  public isEmpty() {
    return this.ma.size == 0;
  }
  
  public get(a: string) {
    let q = this.ma.get(a);
    if (q) {
      return q;
    } else {
      return 0n;
    }
  }

  // cardano-js-sdk assetId is "normalized" i.e. the concatenation of the hex
  // policy id and the hex asset name without a dot separator. so we use the same
  // convention
  public normalizeAsset(value: string): string {
    const normalizedValue = value.split('.').join('');
    if (normalizedValue.length > 0 && !/^[\da-f]+$/i.test(normalizedValue)) {
      throw new Error('normalizeAsset: expected hex string');
    }
    if (normalizedValue.length % 2 != 0) {
      throw new Error('normalizeAsset: odd length of asset');
    }
    if (normalizedValue.length > 120) throw new Error('normalizeAsset: asset longer than 120');
    if (normalizedValue.length < 56) throw new Error('normalizeAsset: asset shorter than 56');
    return normalizedValue;
  }

  public addAsset(aRaw: string, amount: bigint) {
    let a = "";
    if (aRaw != "" && aRaw != "ada.lovelace") {
      a = this.normalizeAsset(aRaw);
    }
    let q = this.ma.get(a);
    if (q) {
      this.ma.set(a, q + amount);
    } else {
      this.ma.set(a, amount);
    }
  }

  public contains(ma: Multiasset) {
    for (const [otherAsset, otherQuantity] of ma) {
      if (this.get(otherAsset) < otherQuantity) {
        return false;
      }
    }
    return true;
  }

  public addMultiasset(ma: Multiasset) {
    for (const [otherAsset, otherQuantity] of ma) {
      this.addAsset(otherAsset, otherQuantity);
    }
  }

  public unwrap(): [bigint, Map<AssetId, bigint>] {
    let coin = 0n;
    let result = new Map();
    for (const [k, v] of this.ma) {
      if (k == "") {
        coin = v;
      } else {
        let assetId = Core.AssetId(k);
        result.set(assetId, v);
      }
    }
    return [coin, result];
  }

  public toJSON(): string {
    let [coin, ma] = this.unwrap();
    let obj = { "": String(coin) };
    for (let [asset, quantity] of ma) {
      obj[asset] = String(quantity);
    }
    return JSON.stringify(obj);
  }

  public static fromJSON(s: string): Multiasset {
    let ret = new Multiasset();
    let o = JSON.parse(s);
    if (typeof(o) != "object") {
      throw new Error("expected object");
    }
    for (let [asset, quantity] of Object.entries(o)) {
      ret.addAsset(asset, BigInt(quantity));
    }
    return ret;
  }

  public addCardanoSdkValue(value: Core.Value) {
    this.addAsset("", value.coin());
    let ma = value.multiasset();
    if (!ma) {
      return;
    }
    for (let [assetId, amount] of ma) {
      this.addAsset(assetId, amount);
    }
  }

  public toCoreValue(): Core.Value {
    let [coin, ma] = this.unwrap();
    let output = new Core.Value(coin);
    output.setMultiasset(ma);
    return output;
  }

  *[Symbol.iterator]() {
    for (const [k,v] of this.ma) {
      yield [k, v];
    }
  }
}

// Collect utxos in the wallet containing the supplied asset until the amount is
// met. Utxos whose only native asset is the one supplied are preferred, but
// utxos with other native assets are used if needed (the extraneous assets are
// returned as change). Utxos in `used` are skipped, and the chosen utxos are
// added to it, so that repeated calls choose disjoint utxos. Utxos with datums
// are skipped unless the datum is an inline bytestring in `allowedDatums` (hex),
// e.g. the payout of a swap order we placed.
async function collectChangeSingleAsset(provider: Provider, address: Core.Address, asset: string, amount: bigint, used: Set<string> = new Set(), allowedDatums: Set<string> = new Set()): Promise<Core.TransactionUnspentOutput[]> {
  let utxos = await provider.getUnspentOutputs(address);
  utxos = utxos.filter(utxo => {
    // Skip utxos that do not contain our desired asset
    let ma = utxo.output().amount().multiasset();
    if (!ma || !ma.get(asset)) {
      return false;
    }
    // Skip utxos with scripts
    if (utxo.output().scriptRef()) {
      return false;
    }
    // Skip utxos with datums, other than explicitly allowed ones
    let datum = utxo.output().datum();
    if (datum) {
      let bytes = datum.asInlineData()?.asBoundedBytes();
      if (!bytes || !allowedDatums.has(bytes.toHex())) {
        return false;
      }
    }
    return !used.has(txref(utxo));
  });
  let byAmount = compareUtxoByAsset(Core.AssetId(asset));
  utxos.sort((a, b) => {
    let aSingle = a.output().amount().multiasset()!.size == 1;
    let bSingle = b.output().amount().multiasset()!.size == 1;
    if (aSingle != bSingle) {
      return aSingle ? -1 : 1;
    }
    return byAmount(a, b);
  });
  let change = [];
  let sum = 0n;
  for (const utxo of utxos) {
    used.add(txref(utxo));
    change.push(utxo);
    sum += BigInt(utxo.output().amount().multiasset().get(Core.AssetId(asset)));
    if (sum >= amount) {
      return change;
    }
  }
  throw new Error(`Couldn't find enough change: want ${amount} but only ${sum} is available from among ${change.length} eligible change utxos`);
}

// Collect all available (non-script, non-datum) change utxos in the wallet
// until the total value meets the supplied multiasset value. The resulting
// change set may contain extraneous assets. Tries to optimize somewhat by
// picking the largest available utxos for each needed asset.
async function collectChangeMa(provider: Provider, address: Core.Address, multiasset: Multiasset): Promise<Core.TransactionUnspentOutput[]> {
  let utxos = await provider.getUnspentOutputs(address);
  for (let utxo of utxos) {
    console.log(`${utxo.input().transactionId()}`);
  }
  let change = new Set();
  let sum = 0n;
  let utxosByAsset: Map<string, Core.TransactionUnspentOutput[]> = new Map();
  // For each asset that we want, make a copy of our utxo list in descending order of quantity of that asset
  for (const [asset, quantity] of multiasset) {
    if (asset == "") {
      let utxosCopy = [...utxos];
      utxosCopy.sort(compareUtxoByAsset(null));
      utxosByAsset.set(asset, utxosCopy);
    } else {
      let utxosCopy = [...utxos];
      utxosCopy.sort(compareUtxoByAsset(Core.AssetId(asset)));
      utxosByAsset.set(asset, utxosCopy);
    }
  }
  // For each asset that we want, add utxos in order from most to least until
  // we have enough of that asset
  let have: Multiasset = new Multiasset();
  for (const [asset, need] of multiasset) {
    console.log(`Asset is '${asset}'`);
    if (need == 0n) {
      continue;
    }
    for (const utxo of utxosByAsset.get(asset)) {
      let txid = utxo.input().transactionId();
      let txix = utxo.input().index();
      console.log(`  Considering utxo ${txid}#${txix}`);
      // Skip utxos with scripts
      if (utxo.output().scriptRef()) {
        continue;
      }
      // Skip utxos with datums
      if (utxo.output().datum()) {
        continue;
      }

      if (change.has(utxo)) {
        console.log(`  Ignoring, because we have already added this to change`);
        continue;
      }
      
      if (asset == "") {
        console.log(`  Adding this utxo`);
        let quantity = utxo.output().amount().coin();
        console.log(`    have += '${asset}': ${quantity}`);
        have.addAsset(asset, quantity);
        for (const [asset, quantity] of utxo.output().amount().multiasset()) {
          console.log(`    have += '${asset}': ${quantity}`);
          have.addAsset(asset, quantity);
        }
        change.add(utxo);
      } else {
        console.log(`  Adding this utxo`);
        for (const [k, v] of utxo.output().amount().multiasset()) {
          console.log(`  Ma ${k} ${v}`);
        }
        let quantity = utxo.output().amount().multiasset().get(Core.AssetId(asset));
        if (quantity) {
          for (const [asset, quantity] of utxo.output().amount().multiasset()) {
            console.log(`    have += '${asset}': ${quantity}`);
            have.addAsset(asset, quantity);
          }
          change.add(utxo);
        } else {
          console.log(`    the utxo has none of '${asset}'`);
        }
      }

      if (have.get(asset) >= need) {
        console.log(`  We have enough of '${asset}'`);
        break;
      }
    }
    if (have.get(asset) < need) {
      for (let [k, v] of have) {
        console.log(`We have ${v} of ${k} (${have.get(k)})`);
      }
      throw new Error(`Couldn't find enough change: want ${need} of asset '${asset}' but only ${have.get(asset)} is available from among ${change.size} eligible change utxos`);      
    }
  }
  return change;
}

async function collectChangeAllowingAssets(provider: Provider, address: Core.Address, amount: bigint): Promise<Core.TransactionUnspentOutput[]> {
  let utxos = await provider.getUnspentOutputs(address);
  let change = [];
  let sum = 0n;
  utxos.sort(compareUtxo);
  for (const utxo of utxos) {
    // Skip utxos with scripts
    if (utxo.output().scriptRef()) {
      continue;
    }
    // Skip utxos with datums
    if (utxo.output().datum()) {
      continue;
    }
    change.push(utxo);
    sum += utxo.output().amount().coin();
    if (sum >= amount) {
      return change;
    }
  }
  throw new Error(`Couldn't find enough change: want ${amount} but only ${sum} is available from among ${change.length} eligible change utxos`);
}

// Collect many change utxos to meet a desired total
async function collectChange(provider: Provider, address: Core.Address, amount: bigint): Promise<Core.TransactionUnspentOutput[]> {
  let utxos = await provider.getUnspentOutputs(address);
  let change = [];
  let sum = 0n;
  utxos.sort(compareUtxo);
  for (const utxo of utxos) {
    // Skip utxos with assets
    let ma = utxo.output().amount().multiasset();
    if (ma != undefined && ma.size > 0) {
      continue;
    }
    // Skip utxos with scripts
    if (utxo.output().scriptRef()) {
      continue;
    }
    // Skip utxos with datums
    if (utxo.output().datum()) {
      continue;
    }
    change.push(utxo);
    sum += utxo.output().amount().coin();
    if (sum >= amount) {
      return change;
    }
  }
  throw new Error(`Couldn't find enough change: want ${amount} but only ${sum} is available from among ${change.length} eligible change utxos`);
}

async function fanout(blaze: Blaze<Provider, Wallet>, provider: Provider, wallet: Core.Address, changeUtxos: Core.TransactionUnspentOutput[], count: bigint, submit: boolean, forceSubmit: boolean, txLogDir: string): Core.TransactionUnspentOutput[] {
  const tx = blaze.newTransaction();

  let available = 0n;
  for (let change of changeUtxos) {
    tx.addInput(change);
    available += change.output().amount().coin();
  }
  available -= 3_000_000n;

  let dividend = available / count;

  for (let i = 0n; i < count; i++) {
    tx.payAssets(
      wallet,
      new Value(dividend)
    );
  }

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });

  if (forceSubmit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    await blaze.submitTransaction(completed);
    console.log(`${completed.toCbor()}`);
    console.log("Submitted");
    return getOutputs(completed.body());
  } else if (submit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    console.log(`${completed.toCbor()}`);
    const response = await prompt("Type 'submit' to submit");
    if (response == "submit") {
      await blaze.submitTransaction(completed);
      console.log("Submitted");
    }
    return getOutputs(completed.body());
  } else {
    let completed = await tx.complete({ useCoinSelection: false });
    if (txLogDir) {
      let txid = completed.getId();
      fs.writeFileSync(`${txLogDir}/${txid}-fanout.tx`, tx.toCbor());
    }
    console.log(`Please sign and submit this transaction: ${envelope(completed.toCbor())}`);
    return getOutputs(completed.body());
  }
}

async function paySelf(blaze: Blaze<Provider, Wallet>, provider: Provider, wallet: Core.Address, inputs: Core.TransactionUnspentOutput[], submit: boolean, forceSubmit: boolean, txLogDir: string): Core.TransactionUnspentOutput {
  const tx = blaze.newTransaction();

  for (const input of inputs) {
    tx.addInput(input);
  }

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });

  if (forceSubmit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    await blaze.submitTransaction(completed);
    console.log(`${completed.toCbor()}`);
    console.log("Submitted");
    return getOutputs(completed.body())[0];
  } else if (submit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    console.log(`${completed.toCbor()}`);
    const response = await prompt("Type 'submit' to submit");
    if (response == "submit") {
      await blaze.submitTransaction(completed);
      console.log("Submitted");
    }
    return getOutputs(completed.body())[0];
  } else {
    let completed = await tx.complete({ useCoinSelection: false });
    if (txLogDir) {
      let txid = completed.getId();
      fs.writeFileSync(`${txLogDir}/${txid}-pay-self.tx`, tx.toCbor());
    }
    console.log(`Please sign and submit this transaction: ${envelope(completed.toCbor())}`);
    return getOutputs(completed.body())[0];
  }
}

function compareUtxoByAsset(asset: AssetId | null) {
  return function(a: Core.TransactionUnspentOutput, b: Core.TransactionUnspentOutput): number {
    let amountA = asset ? a.output().amount().multiasset().get(asset) : a.output().amount().coin();
    let amountB = asset ? b.output().amount().multiasset().get(asset) : b.output().amount().coin();
    if (amountA > amountB) {
      return -1;
    } else if (amountA < amountB ){
      return 1;
    } else {
      return 0;
    }
  };
}

function compareUtxo(a: Core.TransactionUnspentOutput, b: Core.TransactionUnspentOutput): number {
  if (a.input().transactionId() < b.input().transactionId()) {
    return -1;
  } else if (a.input().transactionId() > b.input().transactionId()) {
    return 1;
  } else {
    if (a.input().index() < b.input().index()) {
      return -1;
    } else if (a.input().index() > b.input().index()) {
      return 1;
    } else {
      return 0;
    }
  }
}

export interface BlueprintScript {
  hash: string,
  validator: string,
}

export interface Blueprint {
  settingsSpend: BlueprintScript,
  poolSpend: BlueprintScript,
  poolManage: BlueprintScript,
  poolStake: BlueprintScript,
}

export function decodeBlueprint(blueprint: string): Blueprint {
  let bp: any = {};
  let o = JSON.parse(blueprint);
  for (let v of o.validators) {
    if (v.title.endsWith("settings.spend")) {
      bp.settingsSpend = {
        hash: v.hash,
        validator: v.compiledCode,
      };
    }
    if (v.title.endsWith("pool.spend")) {
      bp.poolSpend = {
        hash: v.hash,
        validator: v.compiledCode,
      };
    }
    if (v.title.endsWith("pool.manage") || v.title.endsWith("pool.manage.else")) {
      bp.poolManage = {
        hash: v.hash,
        validator: v.compiledCode,
      };
    }
    if (v.title.endsWith("pool_stake.stake") || v.title.endsWith("pool_stake.else")) {
      bp.poolStake = {
        hash: v.hash,
        validator: v.compiledCode,
      };
    }
  }
  return bp as Blueprint;
}

async function buildUpdateFeeManager(args: any): Promise<Core.Transaction> {
  let { blaze, provider } = await setupBlaze(args);

  let bp = decodeBlueprint(fs.readFileSync(args.blueprint, "utf8"));
  let poolAddress = Core.addressFromBech32(args.poolAddress);

  let address = Core.addressFromBech32(args.address);

  let poolIdent = args.poolIdent;
  let pool = await findPoolByIdent(provider, poolAddress, poolIdent);

  if (!pool) {
    throw new Error("can't find pool");
  }

  let poolDatum = pool.output().datum();

  if (!poolDatum) {
    throw new Error("no pool datum");
  }

  // Update pool datum in output
  let pd = poolDatum.asInlineData();
  if (!pd) {
    throw new Error("pool datum is not inline");
  }
  let poolDatumDecoded = decodePoolDatum(decoder(fromHex(pd.toCbor())));
  if (args.updateFees) {
    poolDatumDecoded.askFees = BigInt(args.askFee);
    poolDatumDecoded.bidFees = BigInt(args.bidFee);
  } else if (args.updateFeeManager) {
    poolDatumDecoded.feeManager = JSON.parse(args.feeManager);
  }
  let newPoolDatum = PlutusData.fromCbor(HexBlob(withEncoderHex(encodePoolDatum, poolDatumDecoded)));

  let myChange = await findChange(provider, address, 20_000_000n);

  if (!myChange) {
    throw new Error("can't find change");
  }

  let inputs = [myChange, pool];
  inputs.sort(compareUtxo);

  let poolInputIndex = -1n;
  let ix = 0;
  for (let u of inputs) {
    if (u.output().address().toBech32() == poolAddress.toBech32()) {
      poolInputIndex = BigInt(ix);
      break;
    }
    ix += 1;
  }

  if (poolInputIndex == -1n) {
    throw new Error("can't find pool in inputs (impossible)");
  }

  let poolRedeemer = HexBlob(withEncoderHex(encodePoolSpendRedeemer, {
    tag: "Manage",
  }));

  let poolManageRedeemer = HexBlob(withEncoderHex(encodePoolManageRedeemer, {
    tag: "UpdatePoolFees",
    poolInputIndex: poolInputIndex,
  }));

  const poolManageAddress = new Core.Address({
    type: Core.AddressType.RewardScript,
    networkId: provider.network,
    // See https://github.com/input-output-hk/cardano-js-sdk/blob/a1d85a290e9caed7e2c53ed46a0633e84b307458/packages/core/src/Cardano/Address/RewardAddress.ts#L117
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(bp.poolManage.hash),
    },
  });

  const feeManagerAddress = args.feeManagerAddress;
  let feeManagerRedeemer = args.feeManagerRedeemer;

  let referenceData = fs.readFileSync(args.references, "utf8");
  let referenceRefs = [];
  for (let utxoRef of JSON.parse(referenceData)) {
    referenceRefs.push(
      new TransactionInput(
        TransactionId.fromHexBlob(utxoRef.txHash),
        BigInt(utxoRef.index),
      )
    );
  }
  let references = await provider.resolveUnspentOutputs(referenceRefs);

  let feeManagerScriptBytes = fs.readFileSync(args.feeManagerScript, "utf8");
  let feeManagerScript = Script.newPlutusV3Script(
    new PlutusV3Script(HexBlob(feeManagerScriptBytes))
  );

  let poolManageScript = Script.newPlutusV2Script(
    new PlutusV2Script(HexBlob(bp.poolManage.validator))
  );

  let tx = await blaze
    .newTransaction()

    // Spend the pool.
    .addInput(pool, PlutusData.fromCbor(poolRedeemer))

    // Spend pre-selected change (picked before balancing to ensure pool input
    // index is correct).
    .addInput(myChange)

    // Pay the input pool as an output. The amount is unchanged, and the datum
    // is changed according to the update.
    .lockAssets(poolAddress, pool.output().amount(), newPoolDatum as unknown as Datum)

    // Managing the pool requires invoking the pool manage stake validator. The
    // redeemer tells the validator that we want to update the fee manager.
    .addWithdrawal(
      poolManageAddress.toBech32() as Core.RewardAccount,
      BigInt(0),
      PlutusData.fromCbor(poolManageRedeemer)
    )

    // // The confusingly-named sundaeswap "fee manager" validator which is intended
    // // to be used as the multisig "fee manager" field on a pool. Redeemer
    // // specifies the operation to be performed and demonstrates signatures
    // // authorizing that operation on behalf of the 'owner'.
    .addWithdrawal(
      feeManagerAddress,
      BigInt(0),
      PlutusData.fromCbor(feeManagerRedeemer)
    )

    .useCoinSelector((inputs, dearth) => {
      return {
        selectedInputs: [],
        selectedValue: new Value(0n),
        inputs: [],
        leftoverInputs: [],
      }
    })

  for (let reference of references) {
    tx = tx.addReferenceInput(reference);
  }

  tx = tx.provideScript(poolManageScript);
  tx = tx.provideScript(feeManagerScript);

  // No signers are required since the pool's fee manager is just a stake validator.
  let completed = await tx.complete();
  return completed;
}

interface Signature {
  verificationKey: Buffer,
  signature: Buffer,
}

function parseSignatures(signatures: string): Signature[] {
  let result = [];
  let o = JSON.parse(signatures);
  for (let item of o) {
    if (!item.length || item.length != 2) {
      throw new Error(`invalid signatures object: ${signatures}`);
    }
    let key = fromHex(item[0]);
    let sig = fromHex(item[1]);
    result.push({
      verificationKey: key,
      signature: sig,
    });
  }
  return result;
}

export function prepareUpdate(argv: any) {
  if (argv.updateFees) {
    let updateObject: NewFees = {
      validRange: {
        lowerBound: { boundType: { tag: "NegativeInfinity" }, isInclusive: true },
        upperBound: { boundType: { tag: "PositiveInfinity" }, isInclusive: true },
      },
      newBidFees: BigInt(argv.newBidFees),
      newAskFees: BigInt(argv.newAskFees),
    };
    console.log(withEncoderHex(encodeNewFees, updateObject));
  } else if (argv.updateManager) {
    let updateObject: NewFeeManager = {
      validRange: {
        lowerBound: { boundType: { tag: "NegativeInfinity" }, isInclusive: true },
        upperBound: { boundType: { tag: "PositiveInfinity" }, isInclusive: true },
      },
      feeManager: JSON.parse(argv.feeManager),
    };
    console.log(withEncoderHex(encodeNewFeeManager, updateObject));
  }
}

export async function signMessage(argv: any) {
  const skeyHex = process.env["SKEY_HEX"];
  let key = skeyHex;
  if (key == undefined) {
    throw new Error(`signing key not configured`);
  }
  const signature = await ed.signAsync(argv.message, key);
  console.log("message: " + argv.message);
  console.log("signature: " + Buffer.from(signature).toString('hex'));
}

export async function makeRedeemer(argv: any) {
  if (argv.updateFees) {
    let updateObject = decodeNewFees(decoder(fromHex(argv.updateObject)));
    let signatures = parseSignatures(argv.signatures);
    let redeemer: ConvenienceFeeManagerRedeemerUpdateFee = {
      tag: "UpdateFee",
      newFees: updateObject,
      signatures: signatures,
    };
    console.log("redeemer: " + withEncoderHex(encodeConvenienceFeeManagerRedeemer, redeemer));
    let allValid = true;
    for (let item of signatures) {
      const isValid = await ed.verifyAsync(item.signature, argv.updateObject, item.verificationKey);
      if (!isValid) {
        console.log(`invalid signature: key ${item.verificationKey}`);
      }
    }
    if (allValid) {
      console.log("all signatures are valid");
    }
  } else if (argv.updateManager) {
    let updateObject = decodeNewFeeManager(decoder(fromHex(argv.updateObject)));
    let signatures = parseSignatures(argv.signatures);
    let redeemer: ConvenienceFeeManagerRedeemerUpdateFeeManager = {
      tag: "UpdateFeeManager",
      newFeeManager: updateObject,
      signatures: signatures,
    };
    console.log("redeemer: " + withEncoderHex(encodeConvenienceFeeManagerRedeemer, redeemer));
    let allValid = true;
    for (let item of signatures) {
      const isValid = await ed.verifyAsync(item.signature, argv.updateObject, item.verificationKey);
      if (!isValid) {
        console.log(`invalid signature: key ${item.verificationKey}`);
      }
    }
    if (allValid) {
      console.log("all signatures are valid");
    }
  }
}

export async function updateFeeManager(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);
  let completed = await buildUpdateFeeManager(argv);
  if (argv.submit) {
    let signed = await blaze.signTransaction(completed);
    console.log(`Signed...`);
    let hash = await blaze.submitTransaction(completed);
    console.log(`Submitted (${hash})...`);
    let confirmed = await provider.awaitTransactionConfirmation(hash, 60_000);
    if (confirmed) {
      console.log("Confirmed");
    } else {
      console.log("Couldn't confirm submission");
    }
  } else {
    console.log(`Please sign and submit this transaction: ${completed.toCbor()}`);
  }
}

export async function updatePoolStakeCredential(args: any, pool: Core.TransactionUnspentOutput, change: Core.TransactionUnspentOutput) {
  let { blaze, provider } = await setupBlaze(args);
  let bp = decodeBlueprint(fs.readFileSync(args.blueprint, "utf8"));
  let poolAddress = pool.output().address();

  let address = Core.addressFromBech32(args.address);

  let poolDatum = pool.output().datum()?.asInlineData();
  if (!poolDatum) {
    throw new Error("No pool datum");
  }

  const poolManageAddress = new Core.Address({
    type: Core.AddressType.RewardScript,
    networkId: provider.network,
    // See https://github.com/input-output-hk/cardano-js-sdk/blob/a1d85a290e9caed7e2c53ed46a0633e84b307458/packages/core/src/Cardano/Address/RewardAddress.ts#L117
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(bp.poolManage.hash),
    },
  });

  let poolManageScript = Script.newPlutusV2Script(
    new PlutusV2Script(HexBlob(bp.poolManage.validator))
  );

  let referenceData = fs.readFileSync(args.references, "utf8");
  let referenceRefs = [];
  for (let utxoRef of JSON.parse(referenceData)) {
    referenceRefs.push(
      new TransactionInput(
        TransactionId.fromHexBlob(utxoRef.txHash),
        BigInt(utxoRef.index),
      )
    );
  }
  let references: Core.TransactionUnspentOutput[] = [];
  if (referenceRefs.length > 0) {
    references = await provider.resolveUnspentOutputs(referenceRefs);
  }

  let inputs = [change, pool];
  inputs.sort(compareUtxo);

  let poolInputIndex = -1n;
  let ix = 0;
  for (let u of inputs) {
    if (u.output().address().toBech32() == poolAddress.toBech32()) {
      poolInputIndex = BigInt(ix);
      break;
    }
    ix += 1;
  }

  if (poolInputIndex == -1n) {
    throw new Error("can't find pool in inputs (impossible)");
  }

  let poolRedeemer = HexBlob(withEncoderHex(encodePoolSpendRedeemer, {
    tag: "Manage",
  }));

  let poolManageRedeemer = HexBlob(withEncoderHex(encodePoolManageRedeemer, {
    tag: "WithdrawFees",
    amount: 0n,
    treasuryOutput: 1n,
    poolInput: poolInputIndex,
  }));

  let treasuryDatum = PlutusData.fromCbor(HexBlob("d87980"));
  let treasuryAddress = Core.addressFromBech32(args.treasuryAddress);

  let newPoolAddress = Core.addressFromBech32(args.newPoolAddress);

  let tx = await blaze
    .newTransaction()

    // Spend the pool.
    .addInput(pool, PlutusData.fromCbor(poolRedeemer))

    // Spend pre-selected change (selected manually to support chaining).
    .addInput(change)

    // Pay the input pool as an output. The amount is unchanged, and the datum
    // is changed according to the update.
    .lockAssets(newPoolAddress, pool.output().amount(), poolDatum)

    // We have to withdraw fees in order to change the stake credential. We can
    // withdraw 0 fees, but a treasury output must exist, or else the validator
    // will fail.
    .lockAssets(treasuryAddress, new Value(500_000n), treasuryDatum)

    // Managing the pool requires invoking the pool manage stake validator. The
    // redeemer tells the validator that we want to withdraw fees.
    .addWithdrawal(
      poolManageAddress.toBech32() as Core.RewardAccount,
      BigInt(0),
      PlutusData.fromCbor(poolManageRedeemer)
    )

    // This transaction must be signed by the treasury admin
    .addRequiredSigner(args.treasuryAdminPkhHex)

    .useCoinSelector((inputs, dearth) => {
      return {
        selectedInputs: [],
        selectedValue: new Value(0n),
        inputs: [],
        leftoverInputs: [],
      }
    })

  for (let reference of references) {
    tx = tx.addReferenceInput(reference);
  }

  tx = tx.provideScript(poolManageScript);

  let completed = await tx.complete();
  return completed;
}

export async function updateSinglePoolStakeCredential(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);
  let address = Core.addressFromBech32(argv.address);
  let poolAddress = Core.addressFromBech32(argv.poolAddress);

  let pool = null;
  // the pool policy is the same as the spending validator hash
  let poolPolicy = poolAddress.getProps().paymentPart?.hash;
  if (!poolPolicy) {
    throw new Error("Couldn't get pool policy");
  }
  let poolNft = poolPolicy + "000de140" + argv.poolIdent;
  let knownPool = await provider.getUnspentOutputByNFT(Core.AssetId(poolNft));
  if (knownPool) {
    let datum = knownPool.output().datum();
    if (!datum) {
      throw new Error("invalid datum");
    }
    let datumCbor = (datum.toCore() as any).cbor;
    let pd = decodePoolDatum(decoder(fromHex(datumCbor)));
    let ident = pd.identifier.toString('hex');
    if (ident.slice(0,2) == "60") {
      console.log(ident);
      console.log(knownPool.output().address().getProps().delegationPart);
      console.log(knownPool.input().transactionId(), knownPool.input().index());
    }
    if (pd.identifier.toString('hex') == argv.poolIdent) {
      pool = knownPool;
    }
  }
  if (!pool) {
    throw new Error(`couldn't find the pool ${argv.poolIdent}`);
  }
  let change = await findChange(provider, address, 20_000_000n);
  let completed = await updatePoolStakeCredential(argv, pool, change);
  if (argv.submit) {
    let signed = await blaze.signTransaction(completed);
    console.log(`Signed...`);
    let hash = await blaze.submitTransaction(completed);
    console.log(`Submitted (${hash})...`);
    let confirmed = await provider.awaitTransactionConfirmation(hash, 60_000);
    if (confirmed) {
      console.log("Confirmed");
    } else {
      console.log("Couldn't confirm submission");
    }
  } else {
    console.log(`Please sign and submit this transaction: ${completed.toCbor()}`);
  }
}

// Spend the settings utxo with the SettingsAdminUpdate redeemer and pay it back
// to the settings address with an updated datum. Currently this sets the
// extensions field to an empty map (Pairs<Int, Data>). Ported from addScooper in
// lucid-preview-sundae-aiken.
export async function updateSettingsDatum(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);
  let bp = decodeBlueprint(fs.readFileSync(argv.blueprint, "utf8"));
  let address = Core.addressFromBech32(argv.address);

  const settingsAddress = new Core.Address({
    type: Core.AddressType.EnterpriseScript,
    networkId: provider.network,
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(bp.settingsSpend.hash),
    },
  });
  const settings = await findSettings(provider, settingsAddress, bp.settingsSpend.hash);

  let settingsDatumCbor = settings.output().datum()?.asInlineData()?.toCbor();
  if (!settingsDatumCbor) {
    throw new Error("Couldn't get settings datum");
  }
  let settingsDatum = decodeSettingsDatum(decoder(fromHex(settingsDatumCbor)));
  // Empty CBOR map; extensions is Pairs<Int, Data> on-chain
  settingsDatum.extensions = Buffer.from([0xa0]);

  let newSettingsDatumCbor = withEncoderHex(encodeSettingsDatum, settingsDatum);
  console.log(`old settings datum: ${settingsDatumCbor}`);
  console.log(`new settings datum: ${newSettingsDatumCbor}`);

  let newSettingsDatum = PlutusData.fromCbor(HexBlob(newSettingsDatumCbor));

  // SettingsAdminUpdate
  let settingsRedeemer = PlutusData.fromCbor(HexBlob("d87a9fd8799fffff"));

  let settingsScript = Script.newPlutusV2Script(
    new PlutusV2Script(HexBlob(bp.settingsSpend.validator))
  );

  // The settings admin must sign. --settingsAdminPkhHex is a comma-separated
  // list (e.g. enough keys to satisfy an AtLeast multisig). Defaults to the
  // payment key of --address.
  let signerPkhs: string[] = argv.settingsAdminPkhHex
    ? String(argv.settingsAdminPkhHex).split(",")
    : [address.getProps().paymentPart?.hash].filter((h): h is string => !!h);
  if (signerPkhs.length == 0) {
    throw new Error("Couldn't determine settings admin pkh");
  }

  let change = await findChange(provider, address, 20_000_000n);

  let tx = blaze
    .newTransaction()

    // Spend the settings utxo.
    .addInput(settings, settingsRedeemer)

    // Spend pre-selected change.
    .addInput(change)

    // Pay the settings utxo back with the same value and the updated datum.
    .lockAssets(settings.output().address(), settings.output().amount(), newSettingsDatum as unknown as Datum)

    .useCoinSelector((inputs, dearth) => {
      return {
        selectedInputs: [],
        selectedValue: new Value(0n),
        inputs: [],
        leftoverInputs: [],
      }
    })

    .provideScript(settingsScript);

  for (let s of signerPkhs) {
    tx.addRequiredSigner(Core.Ed25519KeyHashHex(s));
  }

  tx.provideCollateral([change]);

  console.log(`Will complete tx: ${tx.toCbor()}`);

  let completed = await tx.complete();
  if (argv.submit) {
    let signed = await blaze.signTransaction(completed);
    console.log(`Signed...`);
    let hash = await blaze.submitTransaction(completed);
    console.log(`Submitted (${hash})...`);
    let confirmed = await provider.awaitTransactionConfirmation(hash, 60_000);
    if (confirmed) {
      console.log("Confirmed");
    } else {
      console.log("Couldn't confirm submission");
    }
  } else {
    console.log(`Please sign and submit this transaction: ${completed.toCbor()}`);
  }
}

function getPoolDatum(pool: Core.TransactionUnspentOutput): PoolDatum | null {
  let datum = pool.output().datum();
  if (!datum) {
    return null;
  }
  let datumCbor = (datum.toCore() as any).cbor;
  try {
    let pd = decodePoolDatum(decoder(fromHex(datumCbor)));
    return pd;
  } catch (e) {
    return null;
  }
}

function getStablePoolDatum(pool: Core.TransactionUnspentOutput): StablePoolDatum | null {
  let datum = pool.output().datum();
  if (!datum) {
    return null;
  }
  let datumCbor = (datum.toCore() as any).cbor;
  try {
    let pd = decodeStablePoolDatum(decoder(fromHex(datumCbor)));
    return pd;
  } catch (e) {
    return null;
  }
}

// We don't really care about exotic pools with little ada because they won't contribute much to staking rewards
function poolTVL(pool: Core.TransactionUnspentOutput): bigint {
  return pool.output().amount().coin() * 2n;
}

function txref(utxo: Core.TransactionUnspentOutput): string {
  let txid = utxo.input().transactionId();
  let txix = utxo.input().index();
  return `${txid}#${txix}`;
}

function comparePoolTVL(a: Core.TransactionUnspentOutput, b: Core.TransactionUnspentOutput): number {
  let tvlA = poolTVL(a);
  let tvlB = poolTVL(b);
  if (tvlA > tvlB) {
    return -1;
  } else if (tvlA < tvlB) {
    return 1;
  } else {
    return 0;
  }
}

function randomIdentifier(): Buffer {
  return crypto.randomBytes(28);
}

function randomTxId(): Buffer {
  return crypto.randomBytes(32);
}

function makeSettingsNft(settingsScriptHash: Buffer): Buffer {
  return Buffer.concat([settingsScriptHash, Buffer.from("settings", "utf8")]);
}

function makePoolNft(poolScriptHash: Buffer, identifier: Buffer): Buffer {
  let prefix = Buffer.from([0x00, 0x0d, 0xe1, 0x40]);
  return Buffer.concat([poolScriptHash, prefix, identifier]);
}

function makeChange(myAddress: Address, amount: bigint): Core.TransactionUnspentOutput {
  let txid = randomTxId();
  txid[0] = 0x11;
  let input =
    new Core.TransactionInput(
      Core.TransactionId(hexEncodeBuffer(txid)),
      0n
  );

  let output =
    new Core.TransactionOutput(
      myAddress,
      new Core.Value(amount),
  );

  let utxo =
    new Core.TransactionUnspentOutput(input, output);

  return utxo;
}

export function makeTokenChange(myAddress: Address, txId: string, index: bigint, asset: string, amount: bigint): Core.TransactionUnspentOutput {
  let input =
    new Core.TransactionInput(
      Core.TransactionId(txId),
      index,
    );

  let output =
    new Core.TransactionOutput(
      myAddress,
      new Core.Value(
        2_000_000n,
        new Map([
          [Core.AssetId(asset), amount],
        ])
      ),
    );

  return new Core.TransactionUnspentOutput(input, output);
}

function multisigSignature(keyHash: Ed25519KeyHash): MultisigSignature {
  let buf: Buffer = Buffer.from(keyHash.bytes());
  return ({
    tag: "Signature",
    keyHash: buf,
  } as MultisigSignature);
}

function paymentAddress(keyHash: Ed25519KeyHash): CodecAddress {
  return newAddress(Buffer.from(keyHash.bytes()), 121n);
}

function makeSettings(bp: Blueprint, keyHash: Ed25519KeyHash): Core.TransactionUnspentOutput {
  let settingsScriptHash = Buffer.from(bp.settingsSpend.hash, "hex");
  let settingsAddr = new Core.Address({
    type: Core.AddressType.EnterpriseScript,
    networkId: NetworkId.Testnet,
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(bp.settingsSpend.hash),
    },
  });

  let txid = randomTxId();
  txid[0] = 0x00;
  let settingsInput = new Core.TransactionInput(
    Core.TransactionId(hexEncodeBuffer(txid)),
    0n
  );

  let settingsInputOutput =
    new Core.TransactionOutput(
      settingsAddr,
      new Core.Value(
        10_000_000n,
        new Map([
          [Core.AssetId(hexEncodeBuffer(makeSettingsNft(settingsScriptHash))), 1n],
        ])
      ),
    );

  let settingsDatum: SettingsDatum = {
    settingsAdmin: multisigSignature(keyHash),
    metadataAdmin: paymentAddress(keyHash),
    treasuryAdmin: multisigSignature(keyHash),
    treasuryAddress: paymentAddress(keyHash),
    treasuryAllowance: { numerator: 1n, denominator: 10n },
    authorizedScoopers: [Buffer.from(keyHash.bytes())],
    authorizedStakingKeys: [{ tag: 121n, cred: Buffer.from(keyHash.bytes()) }],
    baseFee: 1000000n,
    simpleFee: 1000000n,
    strategyFee: 1000000n,
    poolCreationFee: 1000000n,
  };

  let settingsDatumPd = PlutusData.fromCbor(HexBlob(withEncoderHex(encodeSettingsDatum, settingsDatum)));
  settingsInputOutput.setDatum(new Core.Datum(undefined, settingsDatumPd));

  let settings =
    new Core.TransactionUnspentOutput(
      settingsInput,
      settingsInputOutput
    );

  return settings;
}

function makeRandomPool(bp: Blueprint, keyHash: Ed25519KeyHash): [Core.TransactionUnspentOutput, Buffer] {
  let poolScriptHash = Buffer.from(bp.poolSpend.hash, "hex");
  let poolAddr = new Core.Address({
    type: Core.AddressType.BasePaymentScriptStakeKey,
    networkId: NetworkId.Testnet,
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(bp.poolSpend.hash),
    },
    delegationPart: {
      type: Core.CredentialType.KeyHash,
      hash: Hash28ByteBase16(keyHash.hex()),
    },
  });

  let identifier = randomIdentifier();

  let txid = randomTxId();
  txid[0] = 0x22;

  let poolInput =
    new Core.TransactionInput(
      Core.TransactionId(hexEncodeBuffer(txid)),
      0n
    );

  let rberryPolicy = "99b071ce8580d6a3a11b4902145adb8bfd0d2a03935af8cf66403e15";
  let rberryToken = "524245525259";
  let sberryToken = "534245525259";
  let assetPair: AssetPair =
    [
      [fromHex(rberryPolicy), fromHex(rberryToken)],
      [fromHex(rberryPolicy), fromHex(sberryToken)],
    ];

  let poolInputOutput =
    new Core.TransactionOutput(
      poolAddr,
      new Core.Value(
        23_000_000n,
        new Map([
          [Core.AssetId(rberryPolicy + rberryToken), 100_000_000n],
          [Core.AssetId(rberryPolicy + sberryToken), 100_000_000n],
          [Core.AssetId(hexEncodeBuffer(makePoolNft(poolScriptHash, identifier))), 1n],
        ])
      ),
    );
  let poolDatum: PoolDatum = {
    identifier: identifier,
    assetPair: assetPair,
    circulatingLp: 100_000_000n,
    bidFees: 50n,
    askFees: 50n,
    feeManager: {
      tag: "Signature",
      keyHash: Buffer.from(keyHash.bytes()),
    },
    marketOpen: 0n,
    protocolFees: 20_000_000n,
  };

  let poolDatumPd = PlutusData.fromCbor(HexBlob(withEncoderHex(encodePoolDatum, poolDatum)));
  poolInputOutput.setDatum(new Core.Datum(undefined, poolDatumPd));

  let pool =
    new Core.TransactionUnspentOutput(
      poolInput,
      poolInputOutput
    );

  return [pool, identifier];
}

function makeScriptRef(address: Address, validator: HexBlob) {
  let txid = randomTxId();
  txid[0] = 0xff;

  let refInput =
    new Core.TransactionInput(
      Core.TransactionId(hexEncodeBuffer(txid)),
      0n
    );

  let refInputOutput =
    new Core.TransactionOutput(
      address,
      new Core.Value(100_000_000n),
    );

    let script = Script.newPlutusV2Script(new PlutusV2Script(validator));
    refInputOutput.setScriptRef(script);

    let ref =
      new Core.TransactionUnspentOutput(
        refInput,
        refInputOutput
      );

    return ref;
}

export async function testAutoWithdraw(argv: any) {
  let testSkey = Core.Ed25519PrivateKey.fromNormalBytes(crypto.randomBytes(32));
  let testVkey = await testSkey.toPublic();
  let testPkh = await testVkey.hash();

  console.log(`testPkh: ${testPkh.hex()}`);

  let myAddress = Core.Address.fromBytes(Core.HexBlob("60" + testPkh.hex()));

  let emulator = new Emulator([]);

  let changes = [];
  for (let i = 0; i < 20; i++) {
    let change = makeChange(myAddress, 20_000_000n);
    changes.push(change);
    emulator.addUtxo(change);
  }

  let bp = decodeBlueprint(fs.readFileSync(argv.blueprint, "utf8"));

  let poolIds = [];
  for (let i = 0; i < 10; i++) {
    let [pool, identifier] = makeRandomPool(bp, testPkh);
    poolIds.push(identifier);
    emulator.addUtxo(pool);
  }

  let network = NetworkId.Testnet;

  let poolAddress = new Core.Address({
    type: Core.AddressType.BasePaymentScriptStakeKey,
    networkId: network,
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(bp.poolSpend.hash),
    },
    delegationPart: {
      type: Core.CredentialType.KeyHash,
      hash: Hash28ByteBase16(testPkh.hex()),
    },
  });

  let settings = makeSettings(bp, testPkh);
  emulator.addUtxo(settings);

  let settingsDatumCbor = settings.output().datum()?.asInlineData()?.toCbor();
  if (!settingsDatumCbor) {
    throw new Error("Couldn't get inline datum of settings utxo");
  }
  console.log(`settingsDatumCbor: ${settingsDatumCbor}`);
  let settingsDatum = decodeSettingsDatum(decoder(fromHex(settingsDatumCbor)));

  let treasuryAddr = settingsDatum.treasuryAddress.bytes(network);
  console.log(`treasuryAddr: ${treasuryAddr}`);

  let poolScriptRef = makeScriptRef(myAddress, HexBlob(bp.poolSpend.validator));
  emulator.addUtxo(poolScriptRef);

  let poolManageScriptRef = makeScriptRef(myAddress, HexBlob(bp.poolManage.validator));
  emulator.addUtxo(poolManageScriptRef);

  let references = [poolScriptRef, poolManageScriptRef];

  let provider = new EmulatorProvider(emulator);
  let myWallet = new HotSingleWallet(Ed25519PrivateNormalKeyHex(testSkey.hex()), network, provider);
  let blaze = await Blaze.from(provider, myWallet);

  let options: BuildWithdrawPoolRewards = {
    blaze: blaze,
    provider: provider,
    poolAddress: poolAddress,
    settings: settings,
    change: changes[0],
    targetPool: poolIds[0].toString("hex"),
    signers: testPkh.hex(),
    withdrawnAmount: 10_000_000n,
    remainingAmount: undefined,
    withheldAddress: myAddress,
    references: references,
    blueprint: bp,
    treasuryAddress: Core.Address.fromBytes(Core.HexBlob(treasuryAddr)),
    allowance: settingsDatum.treasuryAllowance,
    treasuryAmount: undefined,
    txLogDir: argv.txLogDir,
  };

  for (let utxo of emulator.utxos()) {
    let txid = txref(utxo);
    let cbor = utxo.output().datum()?.asInlineData()?.toCbor();
    console.log(`${txid}: ${cbor}`);
    console.log(utxo.toCbor());
  }

  const tx = await buildWithdrawPoolRewards(options);
  console.log(`Test tx: ${tx.toCbor()}`);
}

export async function debugConditionedScoop(argv: any) {
  let myAddr = Core.Address.fromBech32("addr_test1vqp4mmnx647vyutfwugav0yvxhl6pdkyg69x4xqzfl4vwwck92a9t");
  let poolAddr = Core.Address.fromBech32("addr_test1xzly6g2kvwgfhdvntwfrct0kz9erfqyntw68yt2lz54kg6kvy7vq4p2hl6wm9jdvpgn80ax3xpkm7yrgnxphtrct3klqnkjjzt");
  let scriptRefAddr = Core.Address.fromBech32("addr_test1wza7ec20249sqg87yu2aqkqp735qa02q6yd93u28gzul93gvc4wuw");
  let poolScriptBytes = fs.readFileSync("poolScript", "utf8");
  let poolScript = Script.newPlutusV3Script(new PlutusV3Script(Core.HexBlob(poolScriptBytes)));
  let genesisOutputs: Core.TransactionOutput[] = [];
  let emulator = new Emulator(genesisOutputs);

  let change1Input =
    new Core.TransactionInput(
      Core.TransactionId("75f9bbb87bea926c8a6b4c8d8aed84b0f0d1b4fb307da4a2b60816af2587009e"),
      0n
    );
  let change1InputOutput =
    new Core.TransactionOutput(
      myAddr,
      new Core.Value(
        8_934_871_210n
      ),
  );
  let change1 =
    new Core.TransactionUnspentOutput(
      change1Input,
      change1InputOutput
    );

  let change2Input =
    new Core.TransactionInput(
      Core.TransactionId("75f9bbb87bea926c8a6b4c8d8aed84b0f0d1b4fb307da4a2b60816af2587009e"),
      1n
    );
  let change2InputOutput =
    new Core.TransactionOutput(
      myAddr,
      new Core.Value(
        8_934_871_210n
      ),
  );
  let change2 =
    new Core.TransactionUnspentOutput(
      change2Input,
      change2InputOutput
    );


  let poolScriptReferenceInput =
    new Core.TransactionInput(
      Core.TransactionId(Core.HexBlob("45394d375379204a64d3fd6987afa83d1dd0c4f14a36094056f136bc21ed07b5")),
      0n
    );
  let poolScriptReferenceInputOutput =
    new Core.TransactionOutput(
      scriptRefAddr,
      new Core.Value(
        57_120_430n
      ),
    );
  poolScriptReferenceInputOutput.setScriptRef(poolScript);
  let poolScriptReference =
    new Core.TransactionUnspentOutput(
      poolScriptReferenceInput,
      poolScriptReferenceInputOutput
    );

  let poolInput =
    new Core.TransactionInput(
      Core.TransactionId(Core.HexBlob("4135f635b4f26859231c696699593781e04ffb8eef4576c9917694dcad61693b")),
      0n
    );

  let poolInputOutput =
    new Core.TransactionOutput(
      poolAddr,
      new Core.Value(
        13_000_000n,
        new Map([
          [Core.AssetId("99b071ce8580d6a3a11b4902145adb8bfd0d2a03935af8cf66403e15524245525259"), 100000n],
          [Core.AssetId("be4d215663909bb5935b923c2df611723480935bb4722d5f152b646a000de140a4745a3d72cd31eba160563dbaa3538b574b21cb4a08aef57e18f457"), 1n],
        ])
      ),
    );
  let poolInputDatum = "d8799f581ca4745a3d72cd31eba160563dbaa3538b574b21cb4a08aef57e18f4579f9f4040ff9f581c99b071ce8580d6a3a11b4902145adb8bfd0d2a03935af8cf66403e1546524245525259ffff1a000f42400a0ad87a80001a002dc6c0d8799f581c60c5ca218d3fa6ba7ecf4697a7a566ead9feb87068fc1229eddcf287ffd8799fd8799fa1581c99b071ce8580d6a3a11b4902145adb8bfd0d2a03935af8cf66403e15a1465342455252591903e8d87980ffffff";
  poolInputOutput.setDatum(new Core.Datum(undefined, PlutusData.fromCbor(Core.HexBlob(poolInputDatum))));

  let pool =
    new Core.TransactionUnspentOutput(
      poolInput,
      poolInputOutput
    );

  emulator.addUtxo(change1);
  emulator.addUtxo(pool);
  emulator.addUtxo(poolScriptReference);

  let provider = new EmulatorProvider(emulator);
  const skeyHex = process.env["SKEY_HEX"];
  if (!skeyHex) {
    throw new Error(`signing key not configured`);
  }

  let myWallet = new HotSingleWallet(Ed25519PrivateNormalKeyHex(skeyHex), provider.network, provider);
  let blaze = await Blaze.from(provider, myWallet);

  let poolScoopRedeemer = PlutusData.fromCbor(Core.HexBlob("d87a9fd8799f00009f9f01d87a8000ffffffff"));

  console.log(`emulator: initialized`);
  let tx = new TxBuilder(emulator.params)
    .addInput(pool, poolScoopRedeemer)
    .addInput(change1)
    .provideCollateral([change2])
    .useEvaluator(emulator.evaluator)
    .addReferenceInput(poolScriptReference)
    .setChangeAddress(myAddr)
    .setNetworkId(provider.network);
  let completed = await tx.complete();

  // HotSingleWallet.signTransaction doesn't mutate the tx, it returns a witness
  // set containing exactly one signature. you have to write it into the tx
  // yourself
  let signature = await myWallet.signTransaction(completed);
  completed.setWitnessSet(signature);

  console.log(`emulator: built tx: ${completed.toCbor()}`);

  let txid = await emulator.submitTransaction(completed);
  console.log(`emulator: submitted tx: ${txid}`);
}

export async function registerStakeAddress(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);
  let address = Core.addressFromBech32(argv.address);

  const cred = {
    type: Core.CredentialType.ScriptHash,
    hash: argv.stakeAddrHash,
  };
  const stakeAddress = new Core.Address({
    type: Core.AddressType.RewardScript,
    networkId: provider.network,
    // See https://github.com/input-output-hk/cardano-js-sdk/blob/a1d85a290e9caed7e2c53ed46a0633e84b307458/packages/core/src/Cardano/Address/RewardAddress.ts#L117
    paymentPart: cred,
  });

  let change = await findChange(provider, address, 20_000_000n);
  let inputs = [change];

  let tx = blaze
    .newTransaction()

    // Spend pre-selected change.
    .addInput(change)

    .setMinimumFee(289741n)

    .addRegisterStake(Core.Credential.fromCore(cred))

    //.useCoinSelector((inputs, dearth) => {
    //  return {
    //    selectedInputs: [],
    //    selectedValue: new Value(0n),
    //    inputs: [],
    //    leftoverInputs: [],
    //  }
    //});

  let completed = await tx.complete();
  if (argv.submit) {
    let signed = await blaze.signTransaction(completed);
    console.log(`Signed...`);
    let hash = await blaze.submitTransaction(completed);
    console.log(`Submitted (${hash})...`);
    let confirmed = await provider.awaitTransactionConfirmation(hash, 60_000);
    if (confirmed) {
      console.log("Confirmed");
    } else {
      console.log("Couldn't confirm submission");
    }
  } else {
    console.log(`Please sign and submit this transaction: ${completed.toCbor()}`);
  }
}

export async function updateAllPoolStakeCredentials(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);
  let address = Core.addressFromBech32(argv.address);
  let knownPools = await provider.getUnspentOutputs(Core.addressFromBech32(argv.poolAddress));
  let valid = 0n;
  let invalid = 0n;
  let pools = [];
  console.log(knownPools.length);
  knownPools.sort(comparePoolTVL);
  for (let knownPool of knownPools) {
    if (pools.length >= argv.count) {
      break;
    }
    let datum = getPoolDatum(knownPool);
    if (!datum) {
      invalid += 1n;
      continue;
    }
    if (datum.circulatingLp == 0n) {
      continue;
    }
    console.log(`${txref(knownPool)}: ${poolTVL(knownPool)}`);
    pools.push(knownPool);
    valid += 1n;
  }
  if (pools.length < argv.count) {
    throw new Error(`couldn't find the desired number of pools: ${pools.length}/${argv.count}`);
  }
  let hashes = [];
  let change = await findChangeMany(provider, address, 7_000_000n, argv.count);
  for (let i = 0; i < argv.count; i++) {
    let thisPool = pools[i];
    let thisChange = change[i];
    let completed;
    try {
      completed = await updatePoolStakeCredential(argv, thisPool, thisChange);
    } catch (e) {
      console.log(`Skipping pool due to error: ${e}`);
      continue;
    }
    if (argv.submit) {
      let signed = await blaze.signTransaction(completed);
      console.log(`Signed...`);
      let hash = await blaze.submitTransaction(completed);
      console.log(`Submitted (${hash})...`);
      hashes.push(hash);
    } else {
      console.log(`Please sign and submit this transaction: ${completed.toCbor()}`);
    }
  }
  for (let hash of hashes) {
    let confirmed = await provider.awaitTransactionConfirmation(hash, 60_000);
    if (confirmed) {
      console.log(`Confirmed ${hash}`);
    } else {
      console.log(`Couldn't confirm hash ${hash}`);
    }
  }
}

interface BuildWithdrawStablePoolRewards {
  blaze: Blaze<Provider, Wallet>,
  provider: Provider,
  settings: Core.TransactionUnspentOutput,
  change: Core.TransactionUnspentOutput,
  targetPool: string,
  signers: string,
  withdrawnAmountFlat: bigint,
  withdrawnAmountA: bigint,
  withdrawnAmountB: bigint,
  remainingAmountFlat: bigint | undefined,
  remainingAmountA: bigint | undefined,
  remainingAmountB: bigint | undefined,
  withheldAddress: Address,
  references: Core.TransactionUnspentOutput[],
  blueprint: Blueprint,
  treasuryAddress: Address,
  poolAddress: Address,
  allowance: { numerator: bigint, denominator: bigint } | undefined,
  treasuryAmountFlat: bigint | undefined,
  treasuryAmountA: bigint | undefined,
  treasuryAmountB: bigint | undefined,
  txLogDir: string,
}

export async function buildWithdrawStablePoolRewards(options: BuildWithdrawStablePoolRewards) {
  let targetPool = await findStablePoolByIdent(options.provider, options.poolAddress, options.targetPool);
  if (!targetPool) {
    throw new Error(`Couldn't find pool utxo with target ident ${options.targetPool}`);
  }
  let targetPoolDatum = targetPool.output().datum();
  if (!targetPoolDatum) {
    throw new Error(`Missing datum on target pool`);
  }
  let targetPoolDatumInline = targetPoolDatum.asInlineData();
  if (!targetPoolDatumInline) {
    throw new Error(`Missing inline datum on target pool`);
  }
  let datumCbor = targetPoolDatumInline.toCbor();
  //console.log(`pool datum: ${datumCbor}`);
  let newPoolDatum = decodeStablePoolDatum(decoder(fromHex(datumCbor)));
  //console.log(`decoded pool datum: ${stringify(newPoolDatum)}`);
  let withdrawnAmountFlat;
  if (options.withdrawnAmountFlat != undefined) {
    withdrawnAmountFlat = BigInt(options.withdrawnAmountFlat);
    newPoolDatum.protocolFees[0] = newPoolDatum.protocolFees[0] - withdrawnAmountFlat;
    if (newPoolDatum.protocolFees[0] < 0n) {
      throw new Error("withdrawal would leave negative protocol fees");
    }
  } else if (options.remainingAmountFlat != undefined) {
    let remainingPoolFees = BigInt(options.remainingAmountFlat);
    withdrawnAmountFlat = newPoolDatum.protocolFees[0] - remainingPoolFees;
    newPoolDatum.protocolFees[0] = remainingPoolFees;
    if (newPoolDatum.protocolFees[0] < 0n) {
      throw new Error("withdrawal would leave negative protocol fees");
    }
  } else {
    throw new Error("must pass either withdrawnAmount or remainingAmount");
  }
  let withdrawnAmountA;
  if (options.withdrawnAmountA != undefined) {
    withdrawnAmountA = BigInt(options.withdrawnAmountA);
    newPoolDatum.protocolFees[1] = newPoolDatum.protocolFees[1] - withdrawnAmountA;
    if (newPoolDatum.protocolFees[1] < 0n) {
      throw new Error("withdrawal would leave negative protocol fees");
    }
  } else if (options.remainingAmountA != undefined) {
    let remainingPoolFees = BigInt(options.remainingAmountA);
    withdrawnAmountA = newPoolDatum.protocolFees[1] - remainingPoolFees;
    newPoolDatum.protocolFees[1] = remainingPoolFees;
    if (newPoolDatum.protocolFees[1] < 0n) {
      throw new Error("withdrawal would leave negative protocol fees");
    }
  } else {
    throw new Error("must pass either withdrawnAmount or remainingAmount");
  }
  let withdrawnAmountB;
  if (options.withdrawnAmountB != undefined) {
    withdrawnAmountB = BigInt(options.withdrawnAmountB);
    newPoolDatum.protocolFees[2] = newPoolDatum.protocolFees[2] - withdrawnAmountB;
    if (newPoolDatum.protocolFees[2] < 0n) {
      throw new Error("withdrawal would leave negative protocol fees");
    }
  } else if (options.remainingAmountB != undefined) {
    let remainingPoolFees = BigInt(options.remainingAmountB);
    withdrawnAmountB = newPoolDatum.protocolFees[2] - remainingPoolFees;
    newPoolDatum.protocolFees[2] = remainingPoolFees;
    if (newPoolDatum.protocolFees[2] < 0n) {
      throw new Error("withdrawal would leave negative protocol fees");
    }
  } else {
    throw new Error("must pass either withdrawnAmount or remainingAmount");
  }

  let toSpend = [];
  toSpend.push(options.change);
  toSpend.push(targetPool);
  toSpend.sort((a, b) => a.input().transactionId() == b.input().transactionId() ? Number(a.input().index() - b.input().index()) : (a.input().transactionId() < b.input().transactionId() ? -1 : 1));
  let poolInputIndex = 0n;
  for (let e of toSpend) {
    if (e.output().address() == targetPool.output().address()) {
      break;
    }
    poolInputIndex = poolInputIndex + 1n;
  }

  let treasuryAmountFlat = 0n;
  let treasuryAmountA = 0n;
  let treasuryAmountB = 0n;
  let withheldFlat = 0n;
  let withheldA = 0n;
  let withheldB = 0n;

  if (options.allowance) {
    let n = options.allowance.denominator - options.allowance.numerator;
    let d = options.allowance.denominator;
    treasuryAmountFlat = n * withdrawnAmountFlat / d;
    treasuryAmountA = n * withdrawnAmountA / d;
    treasuryAmountB = n * withdrawnAmountB / d;
    withheldFlat = withdrawnAmountFlat - treasuryAmountFlat;
    withheldA = withdrawnAmountA - treasuryAmountA;
    withheldB = withdrawnAmountB - treasuryAmountB;
  } else if (options.treasuryAmountFlat && options.treasuryAmountA && options.treasuryAmountB) {
    treasuryAmountFlat = options.treasuryAmountFlat;
    treasuryAmountA = options.treasuryAmountA;
    treasuryAmountB = options.treasuryAmountB;
    withheldFlat = withdrawnAmountFlat - treasuryAmountFlat;
    withheldA = withdrawnAmountA - treasuryAmountA;
    withheldB = withdrawnAmountB - treasuryAmountB;
  } else {
    throw new Error("Must set 'allowance' or 'treasuryAmount' on protocol fees withdraw options");
  }

  const poolManageRedeemer = HexBlob(withEncoderHex(encodeStablePoolManageRedeemer, {
    tag: "WithdrawFees",
    amount: [withdrawnAmountFlat, withdrawnAmountA, withdrawnAmountB],
    treasuryOutput: 1n,
    poolInput: poolInputIndex,
  }));

  let poolSpendRedeemer = HexBlob(withEncoderHex(encodeStablePoolSpendRedeemer, {
    tag: "Manage",
  }));

  let updatedPoolDatum = PlutusData.fromCbor(HexBlob(withEncoderHex(encodeStablePoolDatum, newPoolDatum)));

  const poolManageAddress = new Core.Address({
    type: Core.AddressType.RewardScript,
    networkId: options.provider.network,
    // See https://github.com/input-output-hk/cardano-js-sdk/blob/a1d85a290e9caed7e2c53ed46a0633e84b307458/packages/core/src/Cardano/Address/RewardAddress.ts#L117
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(options.blueprint.poolManage.hash),
    },
  });

  const tx = options.blaze
    .newTransaction()
    .addInput(options.change)
    .addInput(targetPool, PlutusData.fromCbor(poolSpendRedeemer));

  for (let ref of options.references) {
    tx.addReferenceInput(ref);
  }
  tx.addReferenceInput(options.settings);

  for (let s of options.signers.split(",")) {
    tx.addRequiredSigner(Core.Ed25519KeyHashHex(s));
  }

  tx.addWithdrawal(
    poolManageAddress.toBech32() as Core.RewardAccount,
    BigInt(0),
    PlutusData.fromCbor(poolManageRedeemer)
  );

  let coinA = assetClassIsAda(newPoolDatum.assetPair[0])
    ? undefined
    : assetClassToAssetId(newPoolDatum.assetPair[0]);
  let coinB = assetClassToAssetId(newPoolDatum.assetPair[1]);

  let newPoolValue = new Core.Value(targetPool.output().amount().coin());
  let targetPoolMa = targetPool.output().amount().multiasset();
  let newPoolValueMa: Map<Core.AssetId, bigint> = new Map(targetPoolMa ?? new Map());
  newPoolValue.setMultiasset(newPoolValueMa);

  let poolADAReduction = withdrawnAmountFlat;
  if (assetClassIsAda(newPoolDatum.assetPair[0])) {
    poolADAReduction += withdrawnAmountA;
  } else {
    newPoolValueMa.set(coinA!, (newPoolValueMa.get(coinA!) ?? 0n) - withdrawnAmountA);
  }
  newPoolValueMa.set(coinB, (newPoolValueMa.get(coinB) ?? 0n) - withdrawnAmountB);
  newPoolValue.setCoin(newPoolValue.coin() - poolADAReduction);
  newPoolValue.setMultiasset(newPoolValueMa);

  tx.lockAssets(
    targetPool.output().address(),
    newPoolValue,
    updatedPoolDatum
  );

  let treasuryDatum = PlutusData.fromCbor(HexBlob("d87980"));
  let treasuryAmount = new Core.Value(treasuryAmountFlat);
  let treasuryAmountMa = new Map();
  if (assetClassIsAda(newPoolDatum.assetPair[0])) {
    treasuryAmount.setCoin(treasuryAmount.coin() + treasuryAmountA);
  } else {
    if (treasuryAmountA > 0n) {
      treasuryAmountMa.set(coinA!, treasuryAmountA);
    }
  }
  if (treasuryAmountB > 0n) {
    treasuryAmountMa.set(coinB, treasuryAmountB);
  }
  treasuryAmount.setMultiasset(treasuryAmountMa);

  if (options.treasuryAddress.getProps().paymentPart?.type == Core.CredentialType.ScriptHash) {
    tx.lockAssets(
      options.treasuryAddress,
      treasuryAmount,
      treasuryDatum
    );
  } else {
    tx.payAssets(
      options.treasuryAddress,
      treasuryAmount,
      treasuryDatum
    );
  }

  let withheldAmount = new Core.Value(withheldFlat);
  let withheldAmountMa = new Map();
  if (assetClassIsAda(newPoolDatum.assetPair[0])) {
    withheldAmount.setCoin(withheldAmount.coin() + withheldA);
  } else {
    if (withheldA > 0n) {
      withheldAmountMa.set(coinA!, withheldA);
    }
  }
  if (withheldB > 0n) {
    withheldAmountMa.set(coinB, withheldB);
  }
  withheldAmount.setMultiasset(withheldAmountMa);

  if (!valueIsZero(withheldAmount)) {
    tx.payAssets(
      options.withheldAddress,
      withheldAmount
    );
  }

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });

  tx.provideCollateral([options.change]);

  let poolManageScript = Script.newPlutusV3Script(
    new PlutusV3Script(HexBlob(options.blueprint.poolManage.validator))
  );
  tx.provideScript(poolManageScript);

  console.log(`tx (not completed): ${tx.toCbor()}`);
  let completed = await tx.complete({ useCoinSelection: false });
  return completed;
}

interface PoolInput {
  utxo: TransactionUnspentOutput,
  txHash: string,
  protocolFees: bigint,
  ident: string,
}

interface BuildWithdrawPoolRewards {
  blaze: Blaze<Provider, Wallet>,
  provider: Provider,
  settings: Core.TransactionUnspentOutput,
  change: Core.TransactionUnspentOutput,
  targetPool: string,
  signers: string,
  withdrawnAmount: bigint,
  remainingAmount: bigint | undefined,
  withheldAddress: Address,
  references: Core.TransactionUnspentOutput[],
  blueprint: Blueprint,
  treasuryAddress: Address,
  poolAddress: Address,
  allowance: { numerator: bigint, denominator: bigint } | undefined,
  treasuryAmount: bigint | undefined,
  txLogDir: string,
}

async function buildWithdrawPoolRewards(options: BuildWithdrawPoolRewards) {
  let targetPool = await findPoolByIdent(options.provider, options.poolAddress, options.targetPool);
  if (!targetPool) {
    throw new Error(`Couldn't find pool utxo with target ident ${options.targetPool}`);
  }
  let targetPoolDatum = targetPool.output().datum();
  if (!targetPoolDatum) {
    throw new Error(`Missing datum on target pool`);
  }
  let targetPoolDatumInline = targetPoolDatum.asInlineData();
  if (!targetPoolDatumInline) {
    throw new Error(`Missing inline datum on target pool`);
  }
  let datumCbor = targetPoolDatumInline.toCbor();
  //console.log(`pool datum: ${datumCbor}`);
  let newPoolDatum = decodePoolDatum(decoder(fromHex(datumCbor)));
  //console.log(`decoded pool datum: ${stringify(newPoolDatum)}`);
  let withdrawnAmount;
  if (options.withdrawnAmount != undefined) {
    withdrawnAmount = BigInt(options.withdrawnAmount);
    newPoolDatum.protocolFees = newPoolDatum.protocolFees - withdrawnAmount;
  } else if (options.remainingAmount != undefined) {
    let remainingPoolFees = BigInt(options.remainingAmount);
    withdrawnAmount = newPoolDatum.protocolFees - remainingPoolFees;
    newPoolDatum.protocolFees = remainingPoolFees;
  } else {
    throw new Error("must pass either withdrawnAmount or remainingAmount");
  }

  let toSpend = [];
  toSpend.push(options.change);
  toSpend.push(targetPool);
  toSpend.sort((a, b) => a.input().transactionId() == b.input().transactionId() ? Number(a.input().index() - b.input().index()) : (a.input().transactionId() < b.input().transactionId() ? -1 : 1));
  let poolInputIndex = 0n;
  for (let e of toSpend) {
    if (e.output().address() == targetPool.output().address()) {
      break;
    }
    poolInputIndex = poolInputIndex + 1n;
  }

  let treasuryAmount = 0n;
  let withheld = 0n;

  if (options.allowance) {
    let n = options.allowance.denominator - options.allowance.numerator;
    let d = options.allowance.denominator;
    treasuryAmount = n * withdrawnAmount / d + 1n;
    if (treasuryAmount < 1000000n) {
      treasuryAmount = 1000000n;
    }
    withheld = withdrawnAmount - treasuryAmount;
  } else if (options.treasuryAmount) {
    treasuryAmount = options.treasuryAmount;
    withheld = withdrawnAmount - treasuryAmount;
  } else {
    throw new Error("Must set 'allowance' or 'treasuryAmount' on protocol fees withdraw options");
  }

  const poolManageRedeemer = HexBlob(withEncoderHex(encodePoolManageRedeemer, {
    tag: "WithdrawFees",
    amount: withdrawnAmount,
    treasuryOutput: 1n,
    poolInput: poolInputIndex,
  }));

  let poolSpendRedeemer = HexBlob(withEncoderHex(encodePoolSpendRedeemer, {
    tag: "Manage",
  }));
  //console.log(`poolSpendRedeemer: ${poolSpendRedeemer}`);

  let updatedPoolDatum = PlutusData.fromCbor(HexBlob(withEncoderHex(encodePoolDatum, newPoolDatum)));

  const poolManageAddress = new Core.Address({
    type: Core.AddressType.RewardScript,
    networkId: options.provider.network,
    // See https://github.com/input-output-hk/cardano-js-sdk/blob/a1d85a290e9caed7e2c53ed46a0633e84b307458/packages/core/src/Cardano/Address/RewardAddress.ts#L117
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(options.blueprint.poolManage.hash),
    },
  });

  const tx = options.blaze
    .newTransaction()
    .addInput(options.change)
    .addInput(targetPool, PlutusData.fromCbor(poolSpendRedeemer));

  for (let ref of options.references) {
    tx.addReferenceInput(ref);
  }
  tx.addReferenceInput(options.settings);

  for (let s of options.signers.split(",")) {
    tx.addRequiredSigner(Core.Ed25519KeyHashHex(s));
  }

  tx.addWithdrawal(
    poolManageAddress.toBech32() as Core.RewardAccount,
    BigInt(0),
    PlutusData.fromCbor(poolManageRedeemer)
  );

  //let newPoolValue = targetPool.output().amount();
  //newPoolValue.setCoin(newPoolValue.coin() - withdrawnAmount);

  let newPoolValue = new Core.Value(targetPool.output().amount().coin());
  let targetPoolMa = targetPool.output().amount().multiasset();
  if (targetPoolMa) {
    newPoolValue.setMultiasset(new Map(targetPoolMa));
  }
  newPoolValue.setCoin(newPoolValue.coin() - withdrawnAmount);

  tx.lockAssets(
    targetPool.output().address(),
    newPoolValue,
    updatedPoolDatum
  );

  let treasuryDatum = PlutusData.fromCbor(HexBlob("d87980"));

  if (options.treasuryAddress.getProps().paymentPart?.type == Core.CredentialType.ScriptHash) {
    tx.lockAssets(
      options.treasuryAddress,
      new Value(treasuryAmount),
      treasuryDatum
    );
  } else {
    tx.payAssets(
      options.treasuryAddress,
      new Value(treasuryAmount),
      treasuryDatum
    );
  }

  if (withheld != 0n) {
    tx.payAssets(
      options.withheldAddress,
      new Value(withheld)
    );
  }

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });

  tx.provideCollateral([options.change]);

  let poolManageScript = Script.newPlutusV2Script(
    new PlutusV2Script(HexBlob(options.blueprint.poolManage.validator))
  );
  tx.provideScript(poolManageScript);

  console.log(`tx (not completed): ${tx.toCbor()}`);
  let completed = await tx.complete({ useCoinSelection: false });
  return completed;
}

interface PoolInput {
  utxo: TransactionUnspentOutput,
  txHash: string,
  protocolFees: bigint,
  ident: string,
}

interface PoolTodo {
  pool: PoolInput,
  amount: bigint,
  partial: boolean,
}

async function queryPools(provider: Provider, poolAddress: string, needed: bigint): Promise<PoolTodo> {
  let poolUtxos = await provider.getUnspentOutputs(Core.addressFromBech32(poolAddress));
  let pools = [];
  for (let poolUtxo of poolUtxos) {
    try {
      let poolDatum = getPoolDatum(poolUtxo);
      if (poolDatum) {
        if (poolDatum.circulatingLp != 0n) {
          pools.push({
            utxo: poolUtxo,
            txHash: poolUtxo.input().transactionId(),
            protocolFees: poolDatum.protocolFees,
            ident: poolDatum.identifier,
          });
        }
      }
    } catch (e) {
      console.log(`queryPools: ${e}`);
    }
  }
  pools.sort((poolA, poolB) => poolA.protocolFees - poolB.protocolFees > 0 ? -1 : 1);
  let sum = 0n;
  let count = 0;
  let todo = [];
  for (let pool of pools) {
    let canWithdraw = pool.protocolFees - 3_000_000n;
    if (canWithdraw <= needed - sum) {
      todo.push({
        pool: pool,
        amount: canWithdraw,
        partial: false,
      });
      sum += canWithdraw;
      count++;
    } else {
      todo.push({
        pool: pool,
        amount: needed - sum,
        partial: true,
      });
      sum = needed;
      count++;
    }
    if (sum >= needed) {
      break;
    }
  }
  if (sum < needed) {
    throw new Error(`couldn't reach target with available pool funds; only ${sum} is available to withdraw`);
  }
  return todo;
}

async function queryStablePools(provider: Provider, poolAddress: string): Promise<PoolTodo> {
  let poolUtxos = await provider.getUnspentOutputs(Core.addressFromBech32(poolAddress));
  let pools = [];
  for (let poolUtxo of poolUtxos) {
    try {
      let poolDatum = getStablePoolDatum(poolUtxo);
      if (poolDatum) {
        if (poolDatum.circulatingLp != 0n) {
          pools.push({
            utxo: poolUtxo,
            txHash: poolUtxo.input().transactionId(),
            protocolFees: poolDatum.protocolFees,
            ident: poolDatum.identifier,
          });
        }
      }
    } catch (e) {
      console.log(`queryPools: ${e}`);
    }
  }
  pools.sort((poolA, poolB) => poolA.protocolFees[0] - poolB.protocolFees[0] > 0 ? -1 : 1);
  let sum = 0n;
  let count = 0;
  let todo = [];
  for (let pool of pools) {
    let canWithdraw = pool.protocolFees[0] - 3_000_000n;
    if (canWithdraw <= 0n) {
      continue;
    }
    todo.push({
      pool: pool,
      amount: canWithdraw,
      amountA: pool.protocolFees[1],
      amountB: pool.protocolFees[2],
      partial: false,
    });
    sum += canWithdraw;
    count++;
  }
  return todo;
}


// This takes a *builder* as an argument to allow automatic retrying in cases
// where there is contention for one of the tx inputs.
async function submitAndAwaitWithRetry(blaze: Blaze<Provider, Wallet>, buildTx: () => Promise<Transaction>): Promise<{tx: Transaction, id: string}> {
  let confirmed = false;
  while (!confirmed) {
    let tx = await buildTx();
    let hash = await blaze.submitTransaction(tx);
    console.log(`Submitted (${hash})...`);
    confirmed = await blaze.provider.awaitTransactionConfirmation(hash, 60_000);
    if (confirmed) {
      console.log(`Confirmed ${hash}`);
      return { tx, id: confirmed };
    } else {
      console.log(`Couldn't confirm transaction ${hash}; retrying`);
    }
  }
}

type SigningKey =
  | { kind: "normal", hex: string }
  | { kind: "extended", key: Core.Ed25519PrivateKey };

// Accepts both normal (5820) and BIP32 extended (5880, e.g. derived from a mnemonic) cardano-cli signing keys
function readSigningKeyFile(filepath: string): SigningKey {
  let contents = fs.readFileSync(filepath, "utf8");
  let json = JSON.parse(contents) as { cborHex: string };
  let skeyCbor = json.cborHex;
  if (skeyCbor.startsWith("5820") && skeyCbor.length == 4 + 64) {
    return { kind: "normal", hex: skeyCbor.slice(4) };
  } else if (skeyCbor.startsWith("5880") && skeyCbor.length == 4 + 256) {
    // cardano-cli layout is kL || kR || public key || chain code; signing only needs kL || kR
    let extendedHex = skeyCbor.slice(4, 4 + 128);
    return { kind: "extended", key: Core.Ed25519PrivateKey.fromExtendedHex(Core.Ed25519PrivateExtendedKeyHex(extendedHex)) };
  } else {
    throw new Error("readSigningKeyFile: invalid cbor signing key");
  }
}

// HotSingleWallet treats its key as a normal ed25519 seed, which yields the wrong public key for
// extended keys, so sign with the extended key directly and reuse ColdWallet for everything else
class ExtendedKeyWallet extends ColdWallet {
  private signingKey: Core.Ed25519PrivateKey;
  private publicKey: Core.Ed25519PublicKey;

  private constructor(signingKey: Core.Ed25519PrivateKey, publicKey: Core.Ed25519PublicKey, address: Core.Address, networkId: NetworkId, provider: Provider) {
    super(address, networkId, provider);
    this.signingKey = signingKey;
    this.publicKey = publicKey;
  }

  // Without an address, the wallet uses the key's enterprise address, like HotSingleWallet does
  static async create(signingKey: Core.Ed25519PrivateKey, networkId: NetworkId, provider: Provider, address?: Core.Address): Promise<ExtendedKeyWallet> {
    // Extended key operations go through libsodium, which must be initialized first
    await Core.initCrypto();
    let publicKey = await signingKey.toPublic();
    let keyHash = (await publicKey.hash()).hex();
    if (address) {
      let paymentPart = address.getProps().paymentPart;
      if (paymentPart?.type != Core.CredentialType.KeyHash || paymentPart.hash.toString() != keyHash.toString()) {
        throw new Error(`signing key ${keyHash} does not match payment credential of ${address.toBech32()}`);
      }
    } else {
      address = new Core.Address({
        type: Core.AddressType.EnterpriseKey,
        networkId,
        paymentPart: { type: Core.CredentialType.KeyHash, hash: Core.Hash28ByteBase16(keyHash) },
      });
    }
    return new ExtendedKeyWallet(signingKey, publicKey, address, networkId, provider);
  }

  async signTransaction(tx: Core.Transaction, partialSign: boolean = true): Promise<Core.TransactionWitnessSet> {
    if (!partialSign) {
      throw new Error("signTx: extended key wallet only supports partial signing = true");
    }
    let signature = await this.signingKey.sign(Core.HexBlob(tx.getId()));
    let vkw = new Core.VkeyWitness(this.publicKey.hex(), signature.hex());
    let tws = new Core.TransactionWitnessSet();
    tws.setVkeys(Core.CborSet.fromCore([vkw.toCore()], Core.VkeyWitness.fromCore));
    return tws;
  }
}

export async function setupBlaze(args: any): Promise<{ blaze: Blaze<Provider, Wallet>, provider: Provider }> {
  let isMainnet = args.mainnet || false;
  let skeyFilePath = args.skeyFile;
  const projectId = process.env["BLOCKFROST_PROJECT_ID"];
  if (!projectId) {
    throw new Error("Missing blockfrost key");
  }

  let provider: Provider;
  if (isMainnet) {
    provider = new Blockfrost({
      network: "cardano-mainnet",
      projectId,
    });
  } else {
    provider = new Blockfrost({
      network: "cardano-preview",
      projectId,
    });
  }

  let network: NetworkId;
  if (isMainnet) {
    network = NetworkId.Mainnet;
  } else {
    network = NetworkId.Testnet;
  }

  let wallet: Wallet;
  if (skeyFilePath) {
    let skey = readSigningKeyFile(skeyFilePath);
    if (skey.kind == "normal") {
      wallet = new HotSingleWallet(Ed25519PrivateNormalKeyHex(skey.hex), network, provider);
    } else {
      let address = args.walletAddress ? Core.addressFromBech32(args.walletAddress) : undefined;
      wallet = await ExtendedKeyWallet.create(skey.key, network, provider, address);
    }
  } else {
    wallet = new ColdWallet(Core.addressFromBech32(args.walletAddress), network, provider);
  }

  let blaze = await Blaze.from(provider, wallet);

  return {
    blaze,
    provider,
  };
}

interface PayoutOptions {
  blaze: Blaze<Provider, Wallet>,
  provider: Provider,
  walletAddress: Address,
  poolAddress: string,
  reportFile: string,
  addressesFile: string,
  references: string,
  blueprint: Blueprint,
  withheldAddress: Address,
  submit: boolean | undefined,
  forceSubmit: boolean | undefined,
  protocolFeesSigners: string,
  tokenHoldersDestination: Address,
  txLogDir: string,
  genericStakeAddress: Address,
  sundaePoolStakeAddress: Address,
  genericStakeKeyFile: string,
  treasuryAddress: Address,
  sundaeStakingSigner: string,
}

function makePayoutOptions(argv: any, config: any, blaze: Blaze<Provider, Wallet>, provider: Provider, bp: Blueprint): PayoutOptions {
  return {
    addressesFile: config.addressesFile as string,
    reportFile: argv.reportFile as string,
    poolAddress: config.poolAddress as string,
    blaze: blaze,
    provider: provider,
    walletAddress: Core.addressFromBech32(config.walletAddress as string),
    references: config.referencesFile as string,
    blueprint: bp,
    withheldAddress: Core.addressFromBech32(config.withheldAddress as string),
    submit: argv.submit,
    forceSubmit: argv.forceSubmit,
    protocolFeesSigners: config.protocolFeesSigners as string,
    tokenHoldersDestination: Core.addressFromBech32(config.tokenHoldersDestination as string),
    txLogDir: config.txLogDir,
    genericStakeAddress: Core.addressFromBech32(config.genericStakeAddress as string),
    sundaePoolStakeAddress: Core.addressFromBech32(config.sundaePoolStakeAddress as string),
    genericStakeKeyFile: config.genericStakeKeyFile as string,
    treasuryAddress: Core.addressFromBech32(config.treasuryAddress as string),
    sundaeStakingSigner: config.sundaeStakingSigner as string,
  };
}

export async function payouts(argv: any) {
  let config = JSON.parse(fs.readFileSync(argv.payoutConfig, "utf8"));
  let bp = decodeBlueprint(fs.readFileSync(config.blueprint as string, "utf8"));
  let { blaze, provider } = await setupBlaze({
    mainnet: argv.mainnet,
    skeyFile: argv.skeyFile,
    walletAddress: config.walletAddress,
  });
  let payoutOptions = makePayoutOptions(argv, config, blaze, provider, bp);
  await doPayouts(payoutOptions);
}

async function doPayouts(options: PayoutOptions) {
  await mkdir(options.txLogDir, { recursive: true });

  let addressesJson = fs.readFileSync(options.addressesFile, "utf8");
  let addresses = decodeAddressesFromJson(addressesJson);
  let reportJson = fs.readFileSync(options.reportFile, "utf8");
  let report = decodeReportFromJson(reportJson);
  let payments = computePayments(report, addresses);

  console.log("withdraw protocol fees");

  let stakeWithdrawalsCount = 2;

  let protocolFeesTodo = await queryPools(options.provider, options.poolAddress, report.payments.protocolFeesNeeded);

  let changeNeededCount = BigInt(protocolFeesTodo.length + stakeWithdrawalsCount + 1);
  let totalChangeAmountNeeded = 10_000_000n * changeNeededCount + 3_000_000n;
  let initialChange = await collectChange(options.provider, options.walletAddress, totalChangeAmountNeeded);

  let allChange = await fanout(
    options.blaze,
    options.provider,
    options.walletAddress,
    initialChange,
    changeNeededCount,
    options.submit,
    options.forceSubmit,
    options.txLogDir,
  );

  let genericChange = allChange[0];
  let poolStakeChange = allChange[1];
  let extraChange = allChange[2];
  let protocolFeesChange = allChange.slice(3);

  let autoWithdrawOptions: AutoWithdrawOptions = {
    poolAddress: options.poolAddress,
    needed: report.payments.protocolFeesNeeded,
    walletAddress: options.walletAddress,
    blueprint: options.blueprint,
    blaze: options.blaze,
    provider: options.provider,
    references: options.references,
    submit: options.submit || false,
    forceSubmit: options.forceSubmit || false,
    withheldAddress: options.withheldAddress,
    signers: options.protocolFeesSigners,
    txLogDir: options.txLogDir,
    todo: { pools: protocolFeesTodo, change: protocolFeesChange },
  };

  let { change: protocolFeesChangeUtxos } = await autoWithdrawRewards(autoWithdrawOptions);

  console.log(`withdraw generic staking rewards for ${options.genericStakeAddress.toBech32()}`);
  
  let withdrawableGeneric = await queryRewards(
    options.provider.network == NetworkId.Mainnet,
    options.genericStakeAddress.toBech32(),
  );
  if (!withdrawableGeneric) {
    console.log("couldn't query rewards for generic stake addr");
    process.exit(1);
  }
  let withdrawGenericOptions: BuildWithdrawGenericStake = {
    blaze: options.blaze,
    change: genericChange,
    stakeAddress: options.genericStakeAddress,
    withdrawnAmount: withdrawableGeneric,
    submit: options.submit || false,
    forceSubmit: options.forceSubmit || false,
    stakeKeyFile: options.genericStakeKeyFile,
    txLogDir: options.txLogDir,
  };
  let genericOutput = await buildWithdrawGenericStake(withdrawGenericOptions);

  console.log(`withdraw sundae pool staking rewards for ${options.sundaePoolStakeAddress.toBech32()}`);

  let withdrawableStaking = await queryRewards(
    options.provider.network == NetworkId.Mainnet,
    options.sundaePoolStakeAddress.toBech32(),
  );
  if (!withdrawableStaking) {
    console.log("couldn't query rewards for sundae pool stake addr");
    process.exit(1);
  }
  let withdrawSundaeStakeOptions: BuildWithdrawPoolStakeRewards = {
    blaze: options.blaze,
    provider: options.provider,
    change: poolStakeChange,
    stakeAddress: options.sundaePoolStakeAddress,
    withdrawnAmount: withdrawableStaking,
    submit: options.submit || false,
    forceSubmit: options.forceSubmit || false,
    blueprint: options.blueprint,
    signers: options.sundaeStakingSigner,
    withheldAddress: options.walletAddress,
    treasuryAddress: options.treasuryAddress, // TODO: Derive from settings datum
    txLogDir: options.txLogDir,
  };
  let poolStakeOutput = await buildWithdrawPoolStakeRewards(withdrawSundaeStakeOptions);

  console.log("collecting change for payout tx");

  let output = await paySelf(
    options.blaze,
    options.provider,
    options.walletAddress,
    [...protocolFeesChangeUtxos, genericOutput, poolStakeOutput, extraChange],
    options.submit,
    options.forceSubmit,
    options.txLogDir,
  );

  let buildPayoutOptions: BuildPayoutOptions = {
    changeUtxos: [output],
    blaze: options.blaze,
    report: report,
    tokenHoldersDestination: options.tokenHoldersDestination,
    scooperPayments: payments,
    submit: options.submit,
    forceSubmit: options.forceSubmit,
    addresses: addresses,
    txLogDir: options.txLogDir,
  }

  console.log("building payout tx");

  await payout(buildPayoutOptions);
}

interface AutoWithdrawOptions {
  poolAddress: string,
  needed: bigint,
  walletAddress: Address,
  blueprint: Blueprint,
  stableBlueprint: Blueprint | undefined,
  blaze: Blaze<Provider, Wallet>,
  provider: Provider,
  references: string,
  submit: boolean | undefined,
  forceSubmit: boolean | undefined,
  withheldAddress: Address,
  signers: string,
  txLogDir: string,
  todo: { pools: PoolTodo[], change: Core.TransactionUnspentOutput[] } | undefined,
  stable: boolean | undefined,
  stableBlueprint: Blueprint,
}

export function makeAutoWithdrawOptions(argv: any, blaze: Blaze<Provider, Wallet>, provider: Provider): AutoWithdrawOptions {
  let bp = decodeBlueprint(fs.readFileSync(argv.blueprint, "utf8"));
  let stableBlueprint = undefined;
  if (argv.stable) {
    stableBlueprint = decodeBlueprint(fs.readFileSync(argv.stableBlueprint, "utf8"));
  }
  let needed = 0n;
  if (!argv.stable) {
    let reportJson = fs.readFileSync(argv.reportFile, "utf8");
    let report = decodeReportFromJson(reportJson);
    needed = report.payments.protocolFeesNeeded;
  }
  return {
    poolAddress: argv.poolAddress,
    needed: needed,
    walletAddress: Core.addressFromBech32(argv.walletAddress),
    blueprint: bp,
    stableBlueprint: stableBlueprint,
    blaze: blaze,
    provider: provider,
    references: argv.references,
    submit: argv.submit,
    forceSubmit: argv.forceSubmit,
    signers: argv.signers,
    withheldAddress: Core.addressFromBech32(argv.withheldAddress),
    txLogDir: argv.txLogDir,
    stable: argv.stable,
  }
}

interface Report {
  feesPaid: FeesPaid,
  totalScoopers: bigint,
  payments: ExtraPayments,
  delegatedScoopers: string[],
}

type FeesPaid = Map<string, bigint>;

interface ExtraPayments {
  tokenHoldersFee: bigint,
  yieldFarming: bigint,
  flat: bigint,
  totalPayout: bigint,
  protocolFeesNeeded: bigint,
}

type Addresses = Map<string, Address>;

function decodeAddressesFromJson(json: string): Addresses {
  let obj = JSON.parse(json);
  let addresses = new Map();
  for (const [name, addrs] of Object.entries(obj.scoopers)) {
    let addr = Core.addressFromBech32((addrs as { reward: string }).reward);
    addresses.set(name, addr);
  }
  return addresses;
}

function decodeReportFromJson(json: string): Report {
  let obj = JSON.parse(json);
  let report: Report = {
    feesPaid: new Map(),
    totalScoopers: 0n,
    payments: {
      tokenHoldersFee: 0n,
      yieldFarming: 0n,
      flat: 0n,
      totalPayout: 0n,
      protocolFeesNeeded: 0n,
    },
    delegatedScoopers: [],
  };

  report.delegatedScoopers = obj.delegatedScoopers;

  for (const [scooperName, feesPaid] of Object.entries(obj.feesPaid)) {
    report.feesPaid.set(scooperName, BigInt(feesPaid as number));
  }
  if (!obj.totalScoopers) {
    throw new Error("Missing 'totalScoopers'");
  }
  report.totalScoopers = BigInt(obj.totalScoopers);

  if (!obj.payments) {
    throw new Error("Missing 'payments'");
  }
  if (typeof obj.payments.yieldFarming== undefined) {
    throw new Error("Missing 'payments.yieldFarming'");
  }
  report.payments.yieldFarming = BigInt(obj.payments.yieldFarming);
  if (typeof obj.payments.tokenHoldersFee == undefined) {
    throw new Error("Missing 'payments.tokenHoldersFee'");
  }
  report.payments.tokenHoldersFee = BigInt(obj.payments.tokenHoldersFee);

  if (typeof obj.payments.flat == undefined) {
    throw new Error("Missing 'payments.flat'");
  }
  report.payments.flat = BigInt(obj.payments.flat);

  if (typeof obj.payments.totalPayout == undefined) {
    throw new Error("Missing 'payments.totalPayout'");
  }
  report.payments.totalPayout = BigInt(obj.payments.totalPayout);

  if (typeof obj.payments.protocolFeesNeeded == undefined) {
    throw new Error("Missing 'payments.protocolFeesNeeded'");
  }
  report.payments.protocolFeesNeeded = BigInt(obj.payments.protocolFeesNeeded);

  return report;
}

interface Payment {
  address: Address,
  lovelace: bigint,
}

// Given a revenue report, compute a list of payments to scoopers, and a list of
// additional payments according to the scooper payment agreement
function computePayments(report: Report, addresses: Addresses): Payment[] {
  let payments = [];
  for (const [scooperName, feesPaid] of report.feesPaid) {
    let resolvedAddress = addresses.get(scooperName);
    if (!resolvedAddress) {
      throw new Error(`Couldn't resolve an address for scooper ${scooperName}`);
    }
    let flat = report.payments.flat;
    if (report.delegatedScoopers.includes(scooperName)) {
      // Skip rewards to delegated scoopers 
      flat = 0n;
    }
    let totalPayment = feesPaid + flat;
    payments.push({ address: resolvedAddress, lovelace: totalPayment });
  }
  return payments;
}

function displayPreviousMonth(date: Date) {
  let month = date.getMonth();
  let year = date.getFullYear();
  if (month == 0) {
    year -= 1;
    month = 12;
  }
  return `${year}-${month.toString().padStart(2, '0')}`;
}

interface BuildPayoutOptions {
  changeUtxos: Core.TransactionUnspentOutput[],
  blaze: Blaze<Provider, Wallet>,
  report: Report,
  tokenHoldersDestination: Address,
  yieldFarmingDestination: Address,
  yieldFarmingAmount: bigint,
  scooperPayments: Payment[],
  submit: boolean | undefined,
  forceSubmit: boolean | undefined,
  addresses: Addresses,
  txLogDir: string,
}

export async function doPayout(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);

  let address = Core.addressFromBech32(argv.walletAddress);

  let addressesJson = fs.readFileSync(argv.addressesFile, "utf8");
  let addresses = decodeAddressesFromJson(addressesJson);
  let reportJson = fs.readFileSync(argv.reportFile, "utf8");
  let report = decodeReportFromJson(reportJson);
  let payments = computePayments(report, addresses);

  let need = new Multiasset();
  need.addAsset("", report.payments.totalPayout + 20_000_000n);
  need.addAsset(
    "9a9693a9a37912a5097918f97918d15240c92ab729a0b7c4aa144d7753554e444145",
    BigInt(argv.yieldFarmingAmount),
  );
  let utxos = await collectChangeMa(provider, address, need);

  let options: BuildPayoutOptions = {
    blaze: blaze,
    changeUtxos: utxos,
    report: report,
    yieldFarmingDestination: Core.addressFromBech32(argv.yieldFarmingDestination),
    yieldFarmingAmount: BigInt(argv.yieldFarmingAmount),
    tokenHoldersDestination: Core.addressFromBech32(argv.tokenHoldersDestination),
    submit: argv.submit,
    forceSubmit: argv.forceSubmit,
    scooperPayments: payments,
    addresses: addresses,
    txLogDir: argv.txLogDir,
  };
  await payout(options);
}

interface BuildWithdrawGenericStake {
  blaze: Blaze<Provider, Wallet>,
  change: Core.TransactionUnspentOutput,
  stakeAddress: Address,
  withdrawnAmount: bigint,
  submit: boolean,
  forceSubmit: boolean,
  stakeKeyFile: string,
  txLogDir: string,
}

interface BuildWithdrawPoolStakeRewards {
  blaze: Blaze<Provider, Wallet>,
  provider: Provider,
  change: Core.TransactionUnspentOutput,
  stakeAddress: Address,
  withdrawnAmount: bigint,
  submit: boolean,
  forceSubmit: boolean,
  blueprint: Blueprint,
  signers: string, 
  withheldAddress: Address,
  treasuryAddress: Address,
  txLogDir: string,
}

export async function withdrawGenericStake(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);
  let withdrawable = null;
  if (argv.fetchRewardsAvailable) {
    withdrawable = await queryRewards(!!argv.mainnet, argv.stakeAddress);
  }
  let address = Core.addressFromBech32(argv.walletAddress);
  let change = await findChange(provider, address, 1000000n);
  let options: BuildWithdrawGenericStake = {
    blaze: blaze,
    change: change,
    stakeAddress: Core.addressFromBech32(argv.stakeAddress),
    withdrawnAmount: withdrawable || BigInt(argv.withdrawnAmount),
    submit: argv.submit,
    forceSubmit: argv.forceSubmit,
    stakeKeyFile: argv.stakeKeyFile,
    txLogDir: argv.txLogDir,
  };
  await buildWithdrawGenericStake(options);
}

export async function withdrawPoolStakeRewards(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);
  let withdrawable = null;
  if (argv.fetchRewardsAvailable) {
    withdrawable = await queryRewards(!!argv.mainnet, argv.stakeAddress);
  }
  let bp = decodeBlueprint(fs.readFileSync(argv.blueprint, "utf8"));
  let address = Core.addressFromBech32(argv.walletAddress);
  let change = await findChange(provider, address, 2000000n);
  let options: BuildWithdrawPoolStakeRewards = {
    blaze: blaze,
    provider: provider,
    change: change,
    stakeAddress: Core.addressFromBech32(argv.stakeAddress),
    withdrawnAmount: withdrawable || BigInt(argv.withdrawnAmount),
    submit: argv.submit,
    forceSubmit: argv.forceSubmit,
    blueprint: bp,
    signers: argv.signers as string,
    withheldAddress: Core.addressFromBech32(argv.withheldAddress),
    treasuryAddress: Core.addressFromBech32(argv.treasuryAddress), // TODO: Derive from settings datum
    txLogDir: argv.txLogDir,
  };
  await buildWithdrawPoolStakeRewards(options);
}

async function signWithStakeKey(tx: Transaction, key: Ed25519PrivateKey) {
  const sig = blazeSignMessage(HexBlob(tx.getId()), key.hex());
  console.log("sig");
  console.log(sig);
  const stakePublicKey = await key.toPublic();
  const stakeVkw = new VkeyWitness(stakePublicKey.hex(), sig);
  const vkeys = [stakeVkw.toCore()];
  let tws = new TransactionWitnessSet();
  tws.setVkeys(CborSet.fromCore(vkeys, VkeyWitness.fromCore));
  tx.setWitnessSet(tws);
}

async function buildWithdrawGenericStake(options: BuildWithdrawGenericStake) {
  const tx = options.blaze.newTransaction();

  tx.addInput(options.change);
  
  tx.addWithdrawal(
    options.stakeAddress.toBech32() as Core.RewardAccount,
    options.withdrawnAmount,
  );

  let stakeKey;
  if (options.stakeKeyFile) {
    if (!options.submit && !options.forceSubmit) {
      throw new Error("Must supply a stake key if submit or forceSubmit is passed");
    }
    let stakeKeyHex = fs.readFileSync(options.stakeKeyFile, "utf8");
    stakeKey = Core.Ed25519PrivateKey.fromNormalHex(Ed25519PrivateNormalKeyHex(stakeKeyHex));
  }

  if (options.forceSubmit) {
    let completed = await tx.complete({ useCoinSelection: false });
    await signWithStakeKey(completed, stakeKey);
    await options.blaze.signTransaction(completed);
    await options.blaze.submitTransaction(completed);
    console.log(`${completed.toCbor()}`);
    console.log("Submitted");
    return getOutputs(completed.body())[0];
  } else if (options.submit) {
    let completed = await tx.complete({ useCoinSelection: false });
    await signWithStakeKey(completed, stakeKey);
    await options.blaze.signTransaction(completed);
    console.log(`${completed.toCbor()}`);
    const response = await prompt("Type 'submit' to submit");
    if (response == "submit") {
      await options.blaze.submitTransaction(completed);
      console.log("Submitted");
    }
    return getOutputs(completed.body())[0];
  } else {
    let completed = await tx.complete({ useCoinSelection: false });
    if (options.txLogDir) {
      let txid = completed.getId();
      fs.writeFileSync(`${options.txLogDir}/${txid}-withdraw-generic-stake.tx`, tx.toCbor());
    }
    console.log(`Please sign and submit this transaction: ${envelope(completed.toCbor())}`);
    return getOutputs(completed.body())[0];
  }
}

async function buildWithdrawPoolStakeRewards(options: BuildWithdrawPoolStakeRewards) {
  const tx = options.blaze.newTransaction();

  tx.addInput(options.change);

  let poolStakeRedeemer = HexBlob("00");
  tx.addWithdrawal(options.stakeAddress.toBech32() as Core.RewardAccount, options.withdrawnAmount, PlutusData.fromCbor(poolStakeRedeemer));

  //let withheld = 2_000_000n;
  //let treasuryAmount = options.withdrawnAmount - withheld;

  let treasuryAmount = 2_000_000n;
  let withheld = options.withdrawnAmount - treasuryAmount;

  const settingsAddress = new Core.Address({
    type: Core.AddressType.EnterpriseScript,
    networkId: options.provider.network,
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(options.blueprint.settingsSpend.hash),
    },
  });
  const settings = await findSettings(options.provider, settingsAddress, options.blueprint.settingsSpend.hash);
  tx.addReferenceInput(settings);

  let settingsDatumCbor = settings.output().datum()?.asInlineData()?.toCbor();
  if (!settingsDatumCbor) {
    throw new Error("Couldn't get settings datum");
  }
  let settingsDatum = decodeSettingsDatum(decoder(fromHex(settingsDatumCbor)));

  for (let s of options.signers.split(",")) {
    tx.addRequiredSigner(Core.Ed25519KeyHashHex(s));
  }

  let treasuryDatum = PlutusData.fromCbor(HexBlob("d87980"));

  if (settingsDatum.treasuryAddress.paymentTag == 121n) {
    tx.payAssets(
      options.treasuryAddress,
      new Value(treasuryAmount),
      treasuryDatum,
    );
  } else {
    tx.lockAssets(
      options.treasuryAddress,
      new Value(treasuryAmount),
      treasuryDatum,
    );
  }

  tx.payAssets(
    options.withheldAddress,
    new Value(withheld),
  );

  let poolStakeScript = Script.newPlutusV2Script(
    new PlutusV2Script(HexBlob(options.blueprint.poolStake.validator))
  );
  tx.provideScript(poolStakeScript);

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });

  tx.provideCollateral([options.change]);

  console.log(`Will complete tx: ${tx.toCbor()}`);

  if (options.forceSubmit) {
    let completed = await tx.complete({ useCoinSelection: false });
    await options.blaze.signTransaction(completed);
    await options.blaze.submitTransaction(completed);
    console.log(`${completed.toCbor()}`);
    console.log("Submitted");
    return getOutputs(completed.body())[1];
  } else if (options.submit) {
    let completed = await tx.complete({ useCoinSelection: false });
    await options.blaze.signTransaction(completed);
    console.log(`${completed.toCbor()}`);
    const response = await prompt("Type 'submit' to submit");
    if (response == "submit") {
      await options.blaze.submitTransaction(completed);
      console.log("Submitted");
    }
    return getOutputs(completed.body())[1];
  } else {
    let completed = await tx.complete({ useCoinSelection: false });
    if (options.txLogDir) {
      let txid = completed.getId();
      fs.writeFileSync(`${options.txLogDir}/${txid}-withdraw-sundae-stake.tx`, tx.toCbor());
    }
    console.log(`Please sign and submit this transaction: ${envelope(completed.toCbor())}`);
    return getOutputs(completed.body())[1];
  }
}

async function payout(options: BuildPayoutOptions) {
  const tx = options.blaze.newTransaction();

  for (const change of options.changeUtxos) {
    tx.addInput(change);
  }

  for (const payment of options.scooperPayments) {
    tx.payAssets(payment.address, new Core.Value(payment.lovelace));
  }
  tx.payAssets(
    options.tokenHoldersDestination,
    new Core.Value(options.report.payments.tokenHoldersFee),
  );
  let yieldFarmingSundaeValue = new Multiasset();
  yieldFarmingSundaeValue.addAsset("", 2_000_000);
  yieldFarmingSundaeValue.addAsset(
    "9a9693a9a37912a5097918f97918d15240c92ab729a0b7c4aa144d77.53554e444145",
    options.yieldFarmingAmount,
  );
  tx.payAssets(
    options.yieldFarmingDestination,
    yieldFarmingSundaeValue.toCoreValue(),
  );

  let timestamp = displayPreviousMonth(new Date());

  let mm = new Map([
    [
      "msg", 
      [
        `Sundae Revenue ${timestamp}`
      ]
    ]
  ]);

  let mDatum = Core.Metadatum.fromCore(mm);

  let mContents = new Map();
  mContents.set(674, mDatum);

  let breakdownMeta = new Map();
  for (const [name, fees] of options.report.feesPaid) {
    let address = options.addresses.get(name);
    if (!address) {
      throw new Error(`No known address for ${name}`);
    }
    let paymentCredHash = address.getProps().paymentPart!.hash;
    let flat = options.report.payments.flat;
    // Skip rewards to delegated scoopers
    if (options.report.delegatedScoopers.includes(name)) {
      flat = 0n;
    }
    breakdownMeta.set(
      fromHex(paymentCredHash),
      new Map([
        ["fees", fees],
        ["rewards", flat]
      ]),
    );
  }
  mContents.set(73115, Core.Metadatum.fromCore(breakdownMeta));
  let m = new Core.Metadata(mContents);
  let auxData = Core.AuxiliaryData.fromCore({
    blob: m.toCore(),
  });
  tx.setAuxiliaryData(auxData);

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });

  if (options.forceSubmit) {
    let completed = await tx.complete();
    await options.blaze.signTransaction(completed);
    await options.blaze.submitTransaction(completed);
    console.log(`${completed.toCbor()}`);
    console.log("Submitted");
  } else if (options.submit) {
    let completed = await tx.complete();
    await options.blaze.signTransaction(completed);
    console.log(`${completed.toCbor()}`);
    const response = await prompt("Type 'submit' to submit");
    if (response == "submit") {
      await options.blaze.submitTransaction(completed);
      console.log("Submitted");
    }
  } else {
    console.log(`payout pre-complete: ${tx.toCbor()}`);
    let completed = await tx.complete({ useCoinSelection: false });
    if (options.txLogDir) {
      let txid = completed.getId();
      fs.writeFileSync(`${options.txLogDir}/${txid}-payout.tx`, tx.toCbor());
    }
    console.log(`Please sign and submit this transaction: ${envelope(completed.toCbor())}`);
  }
}

function isChange(utxo: Core.TransactionUnspentOutput): boolean {
  // Skip utxos with assets
  let ma = utxo.output().amount().multiasset();
  if (ma != undefined && ma.size > 0) {
    return false;
  }
  // Skip utxos with scripts
  if (utxo.output().scriptRef()) {
    return false;
  }
  // Skip utxos with datums
  if (utxo.output().datum()) {
    return false;
  }
  if (utxo.output().amount().coin() < 2_000_000n) {
    return false;
  }
  return true;
}

class DryLedger {
  utxos: Map<string, TransactionOutput>;
  constructor() {
    this.utxos = new Map(); 
  }

  getUnspentTransactionOutputs(): Core.TransactionUnspentOutput[] {
    let out = [];
    for (let [s, output] of this.utxos) {
      let [txidHex, index] = s.split("#");
      let utxo = new Core.TransactionUnspentOutput(
        new Core.TransactionInput(Core.TransactionId(txidHex), BigInt(index)),
        output,
      );
      out.push(utxo);
    }
    return out;
  }

  update(transaction: Transaction) {
    let thisTxId = transaction.getId();
    for (let input of transaction.body().inputs().values()) {
      let txinStr = `${input.transactionId()}#${input.index}`;
      this.utxos.delete(txinStr);
    }

    let outputIndex = 0n;
    for (let output of transaction.body().outputs()) {
      let txinStr = `${thisTxId}#${outputIndex}`;
      this.utxos.set(txinStr, output);
      outputIndex += 1n;
    }
  }
}

function getOutputs(txBody: TransactionBody): Core.TransactionUnspentOutput[] {
  let txid = txBody.hash();
  let outs = txBody.outputs();

  let ret = [];
  let i = 0n;
  for (let out of outs) {
    let input = new Core.TransactionInput(txid, i);
    let utxo = new Core.TransactionUnspentOutput(
      input,
      out,
    );
    ret.push(utxo);
    i++;
  }
  return ret;
}

export async function makeChangeUtxos(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);
  const tx = blaze.newTransaction();

  let count = BigInt(argv.count);
  let amount = BigInt(argv.amount);
  let address = Core.addressFromBech32(argv.address);
  
  let changes = await collectChangeAllowingAssets(provider, address, count * amount);

  for (const change of changes) {
    tx.addInput(change);
  }
  
  for (let i = 0n; i < count; i++) {
    tx.payAssets(address, new Core.Value(amount));
  }

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });
  
  if (argv.forceSubmit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    await blaze.submitTransaction(completed);
    console.log(`${completed.toCbor()}`);
    console.log("Submitted");
  } else if (argv.submit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    console.log(`${completed.toCbor()}`);
    const response = await prompt("Type 'submit' to submit");
    if (response == "submit") {
      await blaze.submitTransaction(completed);
      console.log("Submitted");
    }
  } else {
    console.log(`Please sign and submit this transaction: ${tx.toCbor()}`);
  }
}

export async function autoWithdrawRewards(options: AutoWithdrawOptions): TransactionUnspentOutput[] {
  // 1. 'queryPools': Compute optimal set of pools to withdraw from:
  //   a. Query all withdrawable pools
  //   b. Sort by amount of withdrawable funds
  //   c. Select prefix that satisfies needed amount of funds, call the length of this prefix N
  // 2. 'findChangeMany': Provision N change utxos in our wallet
  // 3. For each pool, build and submit a withdrawal TX using the `i`th change utxo (disabling automatic change selection), retrying if the submission fails due to scooper contention (usually at least one of the withdrawals needs to be retried in practice).
  
  let todo;
  let change;
  if (options.todo) {
    todo = options.todo.pools;
    change = options.todo.change;
  } else {
    if (options.stable) {
      todo = await queryStablePools(options.provider, options.poolAddress);
    } else {
      todo = await queryPools(options.provider, options.poolAddress, options.needed);
    }
    change = await findChangeMany(options.provider, options.walletAddress, 7_000_000n, BigInt(todo.length));
  }

  let settingsSpend = options.blueprint.settingsSpend;
  
  const settingsAddress = new Core.Address({
    type: Core.AddressType.EnterpriseScript,
    networkId: options.provider.network,
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(settingsSpend.hash),
    },
  });

  const settings = await findSettings(options.provider, settingsAddress, settingsSpend.hash);
  let settingsDatumCbor = settings.output().datum()?.asInlineData()?.toCbor();
  if (!settingsDatumCbor) {
    throw new Error("Couldn't get settings datum");
  }
  let settingsDatum = decodeSettingsDatum(decoder(fromHex(settingsDatumCbor)));

  let referenceData = fs.readFileSync(options.references, "utf8");
  let referenceRefs = [];
  for (let utxoRef of JSON.parse(referenceData)) {
    referenceRefs.push(
      new TransactionInput(
        TransactionId.fromHexBlob(utxoRef.txHash),
        BigInt(utxoRef.index),
      )
    );
  }
  let references: Core.TransactionUnspentOutput[] = [];
  if (referenceRefs.length > 0) {
    references = await options.provider.resolveUnspentOutputs(referenceRefs);
  }

  let totalWithdrawn = 0n;

  if (options.forceSubmit) {
    const response = await prompt("Do you really want to force submission of all transactions? (yes/no)");
    if (response != "yes") {
      console.log("Aborting");
      return;
    }
  }

  let withdrawnChange = [];
  let rewards = [];

  for (let i = 0; i < todo.length; i++) {
    let thisChange = change[i];
    let targetPool = todo[i].pool.utxo;
    let withdrawOptions: BuildWithdrawPoolRewards | BuildWithdrawStablePoolRewards | undefined = undefined;
    if (options.stable) {
      withdrawOptions = {
        blaze: options.blaze,
        provider: options.provider,
        settings: settings,
        change: thisChange,
        targetPool: todo[i].pool.ident.toString("hex"),
        signers: options.signers,
        withdrawnAmountFlat: todo[i].amount,
        withdrawnAmountA: todo[i].amountA,
        withdrawnAmountB: todo[i].amountB,
        remainingAmountFlat: undefined,
        remainingAmountA: undefined,
        remainingAmountB: undefined,
        allowance: settingsDatum.treasuryAllowance,
        withheldAddress: options.withheldAddress,
        references: references,
        blueprint: options.stableBlueprint,
        treasuryAddress: Core.Address.fromBytes(Core.HexBlob(settingsDatum.treasuryAddress.bytes(options.provider.network))),
        poolAddress: Core.addressFromBech32(options.poolAddress),
        treasuryAmountFlat: undefined,
        treasuryAmountA: undefined,
        treasuryAmountB: undefined,
        txLogDir: options.txLogDir,
      };
    } else {
      withdrawOptions = {
        blaze: options.blaze,
        provider: options.provider,
        settings: settings,
        change: thisChange,
        targetPool: todo[i].pool.ident.toString("hex"),
        signers: options.signers,
        withdrawnAmount: todo[i].amount,
        remainingAmount: undefined,
        allowance: settingsDatum.treasuryAllowance,
        withheldAddress: options.withheldAddress,
        references: references,
        blueprint: options.blueprint,
        treasuryAddress: Core.Address.fromBytes(Core.HexBlob(settingsDatum.treasuryAddress.bytes(options.provider.network))),
        poolAddress: Core.addressFromBech32(options.poolAddress),
        treasuryAmount: undefined,
        txLogDir: options.txLogDir,
      };
    }

    if (options.forceSubmit) {
      let tx = await submitAndAwaitWithRetry(options.blaze, async () => {
        let tx = undefined;
        if (options.stable) {
          tx = await buildWithdrawStablePoolRewards(withdrawOptions);
        } else {
          tx = await buildWithdrawPoolRewards(withdrawOptions);
        }
        await options.blaze.signTransaction(tx);
        console.log(`${tx.toCbor()}`);
        return tx;
      });
      let outs = getOutputs(tx.body());
      withdrawnChange.push(outs[2], outs[3]);
      rewards.push(outs[2]);
    } else if (options.submit) {
      let retry = true;
      let tx = undefined;
      while (retry) {
        if (options.stable) {
          tx = await buildWithdrawStablePoolRewards(withdrawOptions);
        } else {
          tx = await buildWithdrawPoolRewards(withdrawOptions);
        }
        await options.blaze.signTransaction(tx);
        console.log(`${tx.toCbor()}`);
        const response = await prompt("Type 'submit' to submit");
        if (response == "submit") {
          try {
            let submittedId = await options.blaze.submitTransaction(tx);
            console.log(`Submitted ${submittedId}`);
            retry = false;
          } catch (error) {
            console.log(error);
          }
        } else {
          console.log("Aborting auto-withdrawal");
          process.exit(0);
        }
      }
      let outs = getOutputs(tx.body());
      withdrawnChange.push(outs[2], outs[3]);
      rewards.push(outs[2]);
    } else {
      let tx = undefined;
      if (options.stable) {
        tx = await buildWithdrawStablePoolRewards(withdrawOptions);
      } else {
        tx = await buildWithdrawPoolRewards(withdrawOptions);
      }
      let outs = getOutputs(tx.body());
      withdrawnChange.push(outs[2], outs[3]);
      rewards.push(outs[2]);
      console.log(`Please sign and submit this transaction: ${tx.toCbor()}`);
      if (options.txLogDir) {
        let txid = tx.getId();
        fs.writeFileSync(`${options.txLogDir}/${txid}-withdraw-protocol-fees-${i}.tx`, tx.toCbor());
      }
    }
    totalWithdrawn += todo[i].amount;
    console.log(`Total withdrawn so far: ${totalWithdrawn}`);
  }
  return {
    change: withdrawnChange,
    rewards: rewards,
  };
}

async function makePayment(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);
  const tx = blaze.newTransaction();

  let amount = BigInt(argv.amount);
  let wallet = Core.addressFromBech32(argv.walletAddress);
  let destination = Core.addressFromBech32(argv.destination);

  if (argv.coins) {
    let need = new Multiasset(); 
    need.addAsset("", amount);
    for (let coinExpr of argv.coins.split(",")) {
      let [coin, quantity] = coinExpr.split(":");
      let assetId = Core.AssetId(coin);
      need.addAsset(coin, BigInt(quantity));
    }
    let changes = await collectChangeMa(provider, wallet, need);
    for (const change of changes) {
      tx.addInput(change);
    }
    let paymentAmount = need.toCoreValue();
    tx.payAssets(destination, paymentAmount);
  } else {
    let changes = await collectChangeAllowingAssets(provider, wallet, amount/* + 2_000_000n*/);
    for (const change of changes) {
      console.log(change.input().transactionId());
      console.log(change.input().index());
      tx.addInput(change);
    }
    tx.payAssets(destination, new Core.Value(amount));
  }

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });
  
  if (argv.forceSubmit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    await blaze.submitTransaction(completed);
    console.log(`${completed.toCbor()}`);
    console.log("Submitted");
  } else if (argv.submit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    console.log(`${completed.toCbor()}`);
    const response = await prompt("Type 'submit' to submit");
    if (response == "submit") {
      await blaze.submitTransaction(completed);
      console.log("Submitted");
    }
  } else {
    console.log(`Please sign and submit this transaction: ${tx.toCbor()}`);
  }
}

async function payAssets(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);
  const tx = blaze.newTransaction();

  let assetsData = fs.readFileSync(argv.assetsFile, "utf8");
  let toPay = Multiasset.fromJSON(assetsData);
  let wallet = Core.addressFromBech32(argv.walletAddress);
  let destination = Core.addressFromBech32(argv.destination);

  // Add an extra 5 ADA to ensure minutxo is covered
  toPay.addAsset("", 5_000_000n);

  let changes = await collectChangeMa(provider, wallet, toPay);
  for (const change of changes) {
    tx.addInput(change);
  }
  let paymentAmount = toPay.toCoreValue();
  tx.payAssets(destination, paymentAmount);

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });
  
  if (argv.forceSubmit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    await blaze.submitTransaction(completed);
    console.log(`${completed.toCbor()}`);
    console.log("Submitted");
  } else if (argv.submit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    console.log(`${completed.toCbor()}`);
    const response = await prompt("Type 'submit' to submit");
    if (response == "submit") {
      await blaze.submitTransaction(completed);
      console.log("Submitted");
    }
  } else {
    console.log(`Please sign and submit this transaction: ${tx.toCbor()}`);
  }
}

export interface BuildSwapOptions {
  blaze: Blaze<Provider, Wallet>,
  changeUtxos: Core.TransactionUnspentOutput[],
  pool: PoolData,
  walletAddress: Address,
  swapOfferAmount: BigInt,
  offeredAsset: string,
  orderScriptAddress: Address,
  identifier: Uint8Array | undefined,
}

export interface BuildChainedSwapOptions {
  blaze: Blaze<Provider, Wallet>,
  changeUtxos: Core.TransactionUnspentOutput[],
  pool1: PoolData,
  pool2: PoolData,
  walletAddress: Address,
  swapOfferAmount: BigInt,
  offeredAsset: string,
  orderScriptAddress: Address,
}

function fromDot(asset: string) {
  return asset.replaceAll(".", "");
}

async function buildChainedSwap(options: BuildChainedSwapOptions) {
  const tx = options.blaze.newTransaction();

  for (const change of options.changeUtxos) {
    tx.addInput(change);
  }

  let swapType = { type: ESwapType.MARKET, slippage: 0.03 };
  let offeredAsset = options.offeredAsset;
 
  let otherAsset = undefined;
  let isAtoB = true;
  if (offeredAsset == options.pool1.assetA.assetId) {
    otherAsset = options.pool1.assetB.assetId;
  } else if (offeredAsset == options.pool1.assetB.assetId) {
    otherAsset = options.pool1.assetA.assetId;
    isAtoB = false;
  } else { 
    throw new Error(`offered asset ${offeredAsset} is neither of the assets in the pool's coin pair (${options.pool.assetA.assetId}, ${options.pool.assetB.assetId})`);
  }

  if (otherAsset != options.pool2.assetA.assetId && otherAsset != options.pool2.assetB.assetId) {
    throw new Error(`pool of second leg of chained swap does not match contain the other asset of the first pool`);
  }

  // Estimate the amount of otherAsset recieved for the offered amount of
  // offeredAsset
  let estimatedSwapReturn = undefined;

  if (options.pool1.version == EContractVersion.V3) {
    //  pool_take * difference * order_give / (
    //    pool_give * 10000 + order_give * difference
    //  )
    let orderGive = options.swapOfferAmount;
    let poolTake = undefined;
    let poolGive = undefined;
    let difference = options.pool1.protocolFee;
    if (isAtoB) {
      poolTake = options.pool1.liquidity.bReserve;
      poolGive = options.pool1.liquidity.aReserve;
    } else {
      poolTake = options.pool1.liquidity.aReserve;
      poolGive = options.pool1.liquidity.bReserve;
    }
    estimatedSwapReturn =
      poolTake * (1 - fee) * orderGive / (poolGive + orderGive * (1 - fee));
  } else if (options.pool1.version == EContractVersion.StableSwap) {
    // FIXME
  }

  // Build the datum of the second leg, first
  let sup2 = new AssetAmount(
      estimatedSwapReturn,
      { assetId: otherAsset, decimals: 6 },
  );
  let swap2Args = {
    suppliedAsset: sup2,
    swapType,
    pool: options.pool2,
    orderAddresses: {
      DestinationAddress: { address: options.walletAddress.toBech32(), datum: { type: EDatumType.NONE }, },
    },
  };

  let config2 = new SwapConfig(swap2Args);
  let { pool22, orderAddresses2, suppliedAsset2, minReceivable2 } = config2.buildArgs();

  let datumBuilder = new DatumBuilderV3();
  let { inline2 } = datumBuilder.buildSwapDatum({
    ident: pool22.ident,
    destinationAddress: orderAddresses2.DestinationAddress,
    ownerAddress: options.walletAddress.toBech32(),
    order: { minReceived: minReceivable2, offered: suppliedAsset2 },
    scooperFee: 2_500_000,
  });

  // Now build the datum of the first leg, embedding the second leg's datum
  let sup1 = new AssetAmount(
      options.swapOfferAmount,
      { assetId: offeredAsset, decimals: 6 },
  );
  let swap1Args = {
    suppliedAsset: sup1,
    swapType,
    pool: options.pool1,
    orderAddresses: {
      DestinationAddress: { address: options.orderScriptAddress.toBech32(), datum: { type: EDatumType.Inline, bytes: inline2 }, },
    },
  };

  let config1 = new SwapConfig(swap1Args);
  let { pool, orderAddresses, suppliedAsset, minReceivable } = config1.buildArgs();

  let { inline1 } = datumBuilder.buildSwapDatum({
    ident: pool1.ident,
    destinationAddress: orderAddresses.DestinationAddress,
    ownerAddress: options.walletAddress.toBech32(),
    order: { minReceived: minReceivable, offered: suppliedAsset },
    scooperFee: 2_500_000,
  });

  let lockedValue = new Core.Value(7000000);
  if (offeredAsset == "ada.lovelace") {
    lockedValue.setCoin(BigInt(lockedValue.coin()) + options.swapOfferAmount);
  } else {
    let lockedValueMa = new Map();
    lockedValueMa.set(fromDot(offeredAsset), options.swapOfferAmount);
    lockedValue.setMultiasset(lockedValueMa);
  }

  tx.lockAssets(
    options.orderScriptAddress,
    lockedValue,
    Core.PlutusData.fromCbor(Core.HexBlob(inline1)),
  );

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });

  return tx;
}



async function buildSwap(options: BuildSwapOptions) {
  const tx = options.blaze.newTransaction();

  for (const change of options.changeUtxos) {
    tx.addInput(change);
  }

  let swapType = { type: ESwapType.MARKET, slippage: 0.03 };
  let offeredAsset = options.offeredAsset;
  if (offeredAsset != options.pool.assetA.assetId && offeredAsset != options.pool.assetB.assetId) {
    throw new Error(`offered asset ${offeredAsset} is neither of the assets in the pool's coin pair (${options.pool.assetA.assetId}, ${options.pool.assetB.assetId})`);
  }
  let sup = new AssetAmount(
      options.swapOfferAmount,
      { assetId: offeredAsset, decimals: 6 },
  );

  // DatumBuilderV3 mis-serializes inline destination datums (they come out as
  // the integer 1), so we build with no destination datum and patch the
  // identifier in afterwards with withDestinationInlineDatum.
  let destinationAddress = {
    address: options.walletAddress.toBech32(),
    datum: {
      type: EDatumType.NONE,
    },
  };

  let swapArgs = {
    suppliedAsset: sup,
    swapType,
    pool: options.pool,
    orderAddresses: {
      DestinationAddress: destinationAddress,
    },
  };

  let config = new SwapConfig(swapArgs);
  let { pool, orderAddresses, suppliedAsset, minReceivable, referralFee } = config.buildArgs();

  let datumBuilder = new DatumBuilderV3();
  let { inline } = datumBuilder.buildSwapDatum({
    ident: pool.ident,
    destinationAddress: orderAddresses.DestinationAddress,
    ownerAddress: options.walletAddress.toBech32(),
    order: { minReceived: minReceivable, offered: suppliedAsset },
    scooperFee: 2_500_000,
  });

  let lockedValue = new Core.Value(4500000);
  if (offeredAsset == "ada.lovelace") {
    lockedValue.setCoin(BigInt(lockedValue.coin()) + options.swapOfferAmount);
  } else {
    let lockedValueMa = new Map();
    lockedValueMa.set(fromDot(offeredAsset), options.swapOfferAmount);
    lockedValue.setMultiasset(lockedValueMa);
  }

  let orderDatum = Core.PlutusData.fromCbor(Core.HexBlob(inline));
  if (options.identifier) {
    orderDatum = withDestinationInlineDatum(orderDatum, Core.PlutusData.newBytes(options.identifier));
  }

  tx.lockAssets(
    options.orderScriptAddress,
    lockedValue,
    orderDatum,
  );

  tx.useCoinSelector((inputs, dearth) => {
    return {
      selectedInputs: [],
      selectedValue: new Value(0n),
      inputs: [],
      leftoverInputs: [],
    }
  });

  return tx;
}

// Replace the destination datum of a V3 order datum with an inline datum.
// OrderDatum is Constr 0 [pool_ident, owner, max_protocol_fee, destination,
// details, extension]; a Fixed destination is Constr 0 [address, datum]; and
// InlineDatum is Constr 2 [data].
function withDestinationInlineDatum(orderDatum: Core.PlutusData, datum: Core.PlutusData): Core.PlutusData {
  let replaceField = (constr: Core.ConstrPlutusData, index: number, value: Core.PlutusData) => {
    let fields = constr.getData();
    let newFields = new Core.PlutusList();
    for (let i = 0; i < fields.getLength(); i++) {
      newFields.add(i == index ? value : fields.get(i));
    }
    return Core.PlutusData.newConstrPlutusData(new Core.ConstrPlutusData(constr.getAlternative(), newFields));
  };

  let order = orderDatum.asConstrPlutusData();
  let destination = order?.getData().get(3).asConstrPlutusData();
  if (!order || !destination || destination.getAlternative() != 0n) {
    throw new Error("Expected a V3 order datum with a fixed destination");
  }
  let inlineFields = new Core.PlutusList();
  inlineFields.add(datum);
  let inlineDatum = Core.PlutusData.newConstrPlutusData(new Core.ConstrPlutusData(2n, inlineFields));
  let newDestination = replaceField(destination, 1, inlineDatum);
  return replaceField(order, 3, newDestination);
}

function getBestPool(pools: PoolData[]) {
  if (pools.length == 0) {
    throw new Error("No pools");
  }
  // Get best pool by comparing quantity of asset A reserve
  let bestPool = undefined;
  for (let pool of pools) {
    if (pool.version != EContractVersion.V3) {
      continue;
    }
    if (!bestPool) {
      bestPool = pool;
    } else {
      if (pool.liquidity.aReserve > bestPool.liquidity.aReserve) {
        bestPool = pool;
      }
    }
  }
  return bestPool;
}

// Given an asset, find all pools A and B such that
//   A has pair (asset, otherAsset), and
//   B has pair (ada, otherAsset)
async function findChainedPathToAda(queryProvider: QueryProvider, asset: string) {
  let poolsHavingAsset = await queryProvider.findPoolDataByAssetId(asset);
  let poolsHavingAda = await queryProvider.findPoolDataByAssetId("ada.lovelace");

  let links = new Map();
  for (let poolHavingAda of poolsHavingAda) {
    links.set(poolHavingAda.assetB, poolHavingAda);
  }

  let candidates = [];
  for (let poolHavingAsset of poolsHavingAsset) {
    let otherAsset = poolHavingAsset.assetA;
    if (poolHavingAsset.assetA == asset) {
      otherAsset = poolHavingAsset.assetB;
    }
    let adaLink = links.get(poolHavingAsset.otherAsset);
    if (adaLink) {
      candidates.push([poolHavingAsset, adaLink]);
    }
  }

  // TODO: How to choose a best candidate? 

  if (candidates.length == 0) {
    throw new Error("Couldn't find a path to trade this asset to ada");
  }
}

// Convert a concatenated policy+name asset id into the dotted form used by the
// SundaeSwap SDK
function toDot(asset: string) {
  if (asset == "" || asset == "ada.lovelace" || asset.includes(".")) {
    return asset;
  }
  return `${asset.slice(0, 56)}.${asset.slice(56)}`;
}

// Pool versions we can build swap orders for. Stableswaps orders have the same
// datum encoding as V3 orders, but a different order script.
const SUPPORTED_SWAP_VERSIONS = [EContractVersion.V3, EContractVersion.Stableswaps];

// The order script address for the given protocol version, staked with the
// owner's stake credential (as the SDK does)
async function getOrderScriptAddress(queryProvider, version: EContractVersion, network: number, owner: Core.Address): Promise<Core.Address> {
  let params = await queryProvider.getProtocolParamsWithScripts(version);
  let orderValidator = params.blueprint.validators.find(v => v.title == "order.spend");
  if (!orderValidator) {
    throw new Error(`Couldn't find the ${version} order.spend validator in the protocol params`);
  }
  let paymentPart = {
    hash: Core.Hash28ByteBase16(orderValidator.hash),
    type: Core.CredentialType.ScriptHash,
  };
  let stakeCred = owner.asBase()?.getStakeCredential();
  if (!stakeCred) {
    return Core.addressFromCredential(network, Core.Credential.fromCore(paymentPart));
  }
  return new Core.Address({
    type: Core.AddressType.BasePaymentScriptStakeKey,
    paymentPart,
    delegationPart: stakeCred,
    networkId: network,
  });
}

// Drop assets whose swap to ada would return less than minReturn lovelace
// (e.g. a few units of dust left over from a previous swap), since an order
// that receives nothing can't be scooped
async function filterDust(queryProvider, preferredPools, assetsToConvert, minReturn: bigint) {
  let filtered = {};
  for (let [asset, amount] of Object.entries(assetsToConvert)) {
    if (asset == "" || asset == "ada.lovelace") {
      continue;
    }
    let ident = preferredPools[fromDot(asset)]?.pool;
    if (!ident) {
      throw new Error(`No preferred pools entry was provided for this asset (${asset})`);
    }
    let pool = await queryProvider.findPoolDataByIdent({ ident });
    if (!pool) {
      throw new Error(`Failed to find pool by ident (${ident})`);
    }
    let config = new SwapConfig({
      suppliedAsset: new AssetAmount(BigInt(amount), { assetId: toDot(asset), decimals: 6 }),
      swapType: { type: ESwapType.MARKET, slippage: 0.03 },
      pool,
      orderAddresses: { DestinationAddress: { address: "", datum: { type: EDatumType.NONE } } },
    });
    let { minReceivable } = config.buildArgs();
    if (minReceivable.amount < minReturn) {
      console.log(`Skipping dust: ${amount} of ${asset} would return ${minReceivable.amount} (< ${minReturn})`);
      continue;
    }
    filtered[asset] = amount;
  }
  return filtered;
}

async function buildAssetSwaps(blaze, provider, wallet, queryProvider, preferredPools, assetsToConvert, adaChange, orderScriptAddresses: Map<EContractVersion, Core.Address>, settledOrders: Set<string>) {
  let i = 0;
  let identifiers = new Set<string>();
  let txs = [];
  // Native asset change utxos already claimed by a swap in this batch
  let usedUtxos = new Set<string>(adaChange.map(txref));
  for (let [asset, amount] of Object.entries(assetsToConvert)) {
    // Doesn't make sense to convert ADA to ADA
    if (asset == "" || asset == "ada.lovelace") {
      continue;
    }
    asset = fromDot(asset);

    if (!preferredPools[asset]) {
      throw new Error(`No preferred pools entry was provided for this asset (${asset})`);
    }
    console.log(`${preferredPools[asset].pool}`);
    let pool = await queryProvider.findPoolDataByIdent(
      { ident: preferredPools[asset].pool }
    );
    if (!pool) {
      throw new Error(`Failed to find pool by ident (${preferredPools[asset].pool})`);
    }
    if (!SUPPORTED_SWAP_VERSIONS.includes(pool.version)) {
      throw new Error(`Preferred pool ${pool.ident} for ${asset} is a ${pool.version} pool; only ${SUPPORTED_SWAP_VERSIONS.join(" and ")} pools are supported`);
    }
    console.log(`${stringify(pool)}`);

    // The ada change utxos are disjoint from the native asset change utxos
    // because findChangeMany excludes utxos with native assets, while
    // collectChangeMa only includes utxos having the desired asset.
    // However, calling collectChangeMa for asset X may choose utxos with
    // extraneous native assets, which may include asset Y that we also want to
    // convert.
    // The solution is to only collect native asset change utxos that contain
    // only the native asset and ada. This is disjoint per asset and also
    // disjoint from the pure adaChange set.
    let uniqueAdaChange = adaChange[i];

    let nativeAssetChange = await collectChangeSingleAsset(provider, wallet, asset, BigInt(amount), usedUtxos, settledOrders);

    console.log(`ASSET: ${asset}`);

    // A unique identifier for this order. The ada change utxos may share a
    // transaction id (e.g. if they came from the same fanout), so use random
    // bytes instead.
    let identifier = new Uint8Array(randomTxId());

    identifiers.add(identifier.toHex());

    let tx = await buildSwap({
      blaze: blaze,
      pool: pool,
      changeUtxos: [uniqueAdaChange, ...nativeAssetChange],
      offeredAsset: toDot(asset),
      walletAddress: wallet,
      swapOfferAmount: BigInt(amount),
      orderScriptAddress: orderScriptAddresses.get(pool.version)!,
      identifier,
    });

    console.log(`tx: ${tx.toCbor()}`);
    let completed = await tx.complete();
    console.log(`tx completed: ${completed.toCbor()}`);
    txs.push(completed);

    i++;
  }

  return {
    txs,
    identifiers
  };
}

async function convertAssets(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);

  let assetsData = fs.readFileSync(argv.assetsFile, "utf8");
  let wallet = Core.addressFromBech32(argv.walletAddress);

  let preferredPoolsJson = fs.readFileSync(argv.preferredPoolsFile, "utf8");
  let preferredPools = JSON.parse(preferredPoolsJson);

  let queryProvider;
  if (argv.mainnet) {
    queryProvider = new QueryProviderSundaeSwap("mainnet");
  } else {
    queryProvider = new QueryProviderSundaeSwap("preview");
  }

  let assetsToConvert = JSON.parse(assetsData);

  let orderScriptAddresses = new Map<EContractVersion, Core.Address>();
  for (let version of SUPPORTED_SWAP_VERSIONS) {
    let address = await getOrderScriptAddress(queryProvider, version, argv.mainnet ? 1 : 0, wallet);
    orderScriptAddresses.set(version, address);
    console.log(`${version} order script address: ${address.toBech32()}`);
  }

  let adaEarned = 0n;
  // Identifiers of all orders settled so far; their payouts may be spent by
  // later rounds of swaps
  let settledOrders = new Set<string>();
  let minSwapReturn = BigInt(argv.minSwapReturn ?? 1);
  let mustSwap = true;
  while (mustSwap) {
    assetsToConvert = await filterDust(queryProvider, preferredPools, assetsToConvert, minSwapReturn);
    if (Object.keys(assetsToConvert).length == 0) {
      break;
    }

    let adaChange = await findChangeMany(provider, wallet, 7_000_000n, Object.keys(assetsToConvert).length);

    // For each asset that we need to convert, build a list-order
    // swapping that asset to its preferred pool
    let { txs, identifiers } = await buildAssetSwaps(blaze, provider, wallet, queryProvider, preferredPools, assetsToConvert, adaChange, orderScriptAddresses, settledOrders);

    mustSwap = false;
    assetsToConvert = {};

    // Submit all of the asset-swap list-order txes
    for (let completed of txs) {
      await blaze.signTransaction(completed);
      console.log(`${completed.toCbor()}`);
      const response = await prompt("Type 'submit' to submit");
      if (response != "submit") {
        throw new Error("Aborted: not all list-order transactions were submitted");
      }
      await blaze.submitTransaction(completed);
      console.log(`Submitted ${completed.getId()}`);
    }

    // Wait for all of the list-order txes to settle
    let awaitedTxs = [];
    for (let completed of txs) {
      awaitedTxs.push(provider.awaitTransactionConfirmation(completed.getId(), 300_000));
    }
    let confirmations = await Promise.all(awaitedTxs);
    if (!confirmations.every(c => c === true)) {
      throw new Error("Not all list-order transactions have settled");
    }
    console.log("All list-order transactions confirmed; waiting for scoops");

    // Wait for all datums to appear in the wallet
    let settledCount = 0;
    while (true) {
      let unspentOutputs = await provider.getUnspentOutputs(wallet);
      for (let utxo of unspentOutputs) {
        let thisDatum = utxo.output().datum()?.asInlineData()?.asBoundedBytes()?.toHex();
        if (!thisDatum) {
          continue;
        }

        // A new settled order was just discovered; update funds state
        if (!settledOrders.has(thisDatum) && identifiers.has(thisDatum)) {
          settledOrders.add(thisDatum);
          settledCount++;
          let thisValue = utxo.output().amount();

          // If thisValue is pure ada, then we need to tally the surplus ada
          // (i.e. the total ada minus rider and fee). Otherwise, there should
          // be no surplus ada and some native token, and we should add that to
          // the new assetsToConvert.
          let riderAndFee = 4_500_000n;
          let netAda = thisValue.coin() - riderAndFee;
          adaEarned += netAda;
          console.log(`Order ${thisDatum} settled in tx ${utxo.input().transactionId()}: ${netAda} lovelace net`);
          if (thisValue.multiasset()) {
            for (let [asset, quantity] of thisValue.multiasset()) {
              assetsToConvert[asset] = (assetsToConvert[asset] ?? 0n) + quantity;
            }
          }
        }
      }
      if (settledCount >= identifiers.size) {
        break;
      }
      console.log(`${settledCount}/${identifiers.size} orders settled; checking again in 60s`);
      await delay(60_000);
    }

    // All orders have settled. We now know the total ada earned (possibly
    // negative) and the new assetsToConvert (possibly empty if all swaps were
    // to ada). If assetsToConvert is empty, stop here and report the total ada
    // earned across all iterations. Otherwise, issue a new batch of swaps.
    if (Object.keys(assetsToConvert).length != 0) {
      mustSwap = true;
    }
  }
  console.log(`Earned ADA (lovelace): ${adaEarned}`);
  if (argv.convertAssetsOut) {
    await Bun.write(argv.convertAssetsOut, adaEarned.toString());
  }
}

async function doSwap(argv: any) {
  let { blaze, provider } = await setupBlaze(argv);

  let toPay = new Multiasset(); 
  toPay.addAsset("", 4_500_000n + BigInt(argv.swapOfferAmount));

  let wallet = Core.addressFromBech32(argv.walletAddress);

  let changes = await collectChangeMa(provider, wallet, toPay);

  let queryProvider;
  if (argv.mainnet) {
    queryProvider = new QueryProviderSundaeSwap("mainnet");
  } else {
    queryProvider = new QueryProviderSundaeSwap("preview");
  }
  let pools = await queryProvider.findPoolDataByAssetPair(
    argv.assetA,
    argv.assetB,
  );
  if (pools.length == 0) {
    throw new Error("Couldn't find pool for this asset pair");
  }

  // Get best pool by comparing quantity of asset A reserve
  let bestPool = undefined;
  for (let pool of pools) {
    if (pool.version != EContractVersion.V3) {
      continue;
    }
    if (!bestPool) {
      bestPool = pool;
    } else {
      if (pool.liquidity.aReserve > bestPool.liquidity.aReserve) {
        bestPool = pool;
      }
    }
  }

  let identifier = new Uint8Array(randomTxId());
  let tx = await buildSwap({
    blaze: blaze,
    pool: bestPool,
    changeUtxos: changes,
    walletAddress: wallet,
    swapOfferAmount: BigInt(argv.swapOfferAmount),
    offeredAsset: argv.assetA,
    orderScriptAddress: Core.addressFromBech32(argv.orderScriptAddress),
    identifier,
  });
  
  let submittedTx = null;
  if (argv.forceSubmit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    await blaze.submitTransaction(completed);
    console.log(`${completed.toCbor()}`);
    console.log("Submitted");
  } else if (argv.submit) {
    let completed = await tx.complete();
    await blaze.signTransaction(completed);
    console.log(`${completed.toCbor()}`);
    const response = await prompt("Type 'submit' to submit");
    if (response == "submit") {
      await blaze.submitTransaction(completed);
      console.log("Submitted");
      submittedTx = completed;
    }
  } else {
    console.log(`Please sign and submit this transaction: ${tx.toCbor()}`);
    let completed = await tx.complete();
    console.log(`(Completed tx: ${completed.toCbor()})`);
  }

  if (!submittedTx) {
    return;
  }

  let confirmed = await provider.awaitTransactionConfirmation(submittedTx.getId(), 300_000);
  if (!confirmed) {
    throw new Error("list-order transaction did not settle");
  }
  console.log("list-order transaction confirmed; waiting for scoop");

  let assetsEarned = new Multiasset();
  let done = false;
  while (!done) {
    let unspentOutputs = await provider.getUnspentOutputs(wallet);
    for (let utxo of unspentOutputs) {
      let thisDatum = utxo.output().datum()?.asInlineData()?.asBoundedBytes()?.toHex();
      if (!thisDatum) {
        continue;
      }

      if (identifier.toHex() == thisDatum) {
        let thisValue = utxo.output().amount();
        let riderAndFee = 4_500_000n;
        let netAda = thisValue.coin() - riderAndFee;
        assetsEarned.addAsset("", netAda);
        console.log(`Order ${thisDatum} settled in tx ${utxo.input().transactionId()}: ${netAda} lovelace net`);
        if (thisValue.multiasset()) {
          for (let [asset, quantity] of thisValue.multiasset()) {
            assetsEarned.addAsset(asset, quantity);
          }
        }
        done = true;
      }
    }
    if (!done) {
      console.log(`order not yet settled; checking again in 60s`);
      await delay(60_000);
    }
  }
  console.log(`Assets earned: ${assetsEarned.toJSON()}`);
  await Bun.write(argv.rewardsOut, assetsEarned.toJSON());
}

// Given a file describing amounts of various assets in a wallet, swap each of
// those assets to ada. This is useful after withdrawing the rewards from the
// stable pools, since stable pools can have fees in non-ada assets.
async function swapAssetsToAda(argv) {
  let query;
  if (argv.mainnet) {
    query = new QueryProviderSundaeSwap("mainnet");
  } else {
    query = new QueryProviderSundaeSwap("preview");
  }
  //let pools = await query.findPoolDataByAssetPair("", "9a9693a9a37912a5097918f97918d15240c92ab729a0b7c4aa144d77.53554e444145");
  let pools = await query.findPoolDataByAssetPair("", "1f3aec8bfe7ea4fe14c5f121e2a92e301afe414147860d557cac7e34.5553444378");
  if (!pools || pools.length == 0) {
    console.log(`No pools found`);
  }
  for (let pool of pools) {
    console.log(`Pool found: ${pool.ident}`);
  }
}

if (import.meta.main) {
  let argv = minimist(process.argv.slice(2));
  if (argv.buildUpdateFeeManager) {
    await updateFeeManager(argv);
  } else if (argv.prepareUpdate) {
    prepareUpdate(argv);
  } else if (argv.signMessage) {
    await signMessage(argv);
  } else if (argv.makeRedeemer) {
    await makeRedeemer(argv);
  } else if (argv.updateAllPoolStakeCredentials) {
    await updateAllPoolStakeCredentials(argv);
  } else if (argv.updateSinglePoolStakeCredential) {
    await updateSinglePoolStakeCredential(argv);
  } else if (argv.updateSettingsDatum) {
    await updateSettingsDatum(argv);
  } else if (argv.registerStakeAddress) {
    await registerStakeAddress(argv);
  } else if (argv.debugConditionedScoop) {
    await debugConditionedScoop(argv);
  } else if (argv.autoWithdrawRewards) {
    let { blaze, provider } = await setupBlaze(argv);
    let opts = makeAutoWithdrawOptions(argv, blaze, provider);
    let { rewards } = await autoWithdrawRewards(opts);
    let totalWithdrawn = new Multiasset();
    for (let change of rewards) {
      let amount = change.output().amount();
      totalWithdrawn.addAsset("", amount.coin());
      if (amount.multiasset()) {
        for (const [asset, quantity] of amount.multiasset()) {
          totalWithdrawn.addAsset(asset, quantity);
        }
      }
    }
    await Bun.write(argv.rewardsOut, totalWithdrawn.toJSON());
  } else if (argv.testAutoWithdraw) {
    await testAutoWithdraw(argv);
  } else if (argv.doPayouts) {
    await payouts(argv);
  } else if (argv.doPayout) {
    await doPayout(argv);
  } else if (argv.makeChangeUtxos) {
    await makeChangeUtxos(argv);
  } else if (argv.withdrawGenericStake) {
    await withdrawGenericStake(argv);
  } else if (argv.withdrawPoolStakeRewards) {
    await withdrawPoolStakeRewards(argv);
  } else if (argv.makePayment) {
    await makePayment(argv);
  } else if (argv.payAssets) {
    await payAssets(argv);
  } else if (argv.doSwap) {
    await doSwap(argv);
  } else if (argv.convertAssets) {
    await convertAssets(argv);
  }

  process.exit(0);
}
