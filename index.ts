import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as readline from "node:readline/promises";
import { stdin, stdout } from "node:process";
import {
  Address,
  Datum,
  DatumKind,
  Ed25519PrivateNormalKeyHex,
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
  Value,
} from "@blaze-cardano/core";
import { HotSingleWallet, Core, Blaze, Blockfrost, Provider, Wallet } from "@blaze-cardano/sdk";
import { TxBuilder } from "@blaze-cardano/tx";
import { Emulator, EmulatorProvider } from "@blaze-cardano/emulator";
import { Ed25519KeyHash } from "@cardano-sdk/crypto";
import * as ed from "@noble/ed25519";
import minimist from "minimist";
import {
  decoder,
  decodeNewFees,
  decodeNewFeeManager,
  decodePoolDatum,
  decodeSettingsDatum,
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
  newAddress,
  MultisigSignature,
  Address as CodecAddress,
  NewFees,
  NewFeeManager,
  ConvenienceFeeManagerRedeemerUpdateFee,
  ConvenienceFeeManagerRedeemerUpdateFeeManager,
  PoolDatum,
  SettingsDatum,
  AssetPair,
} from "./codec.js";
import {
  fromHex,
  stringify,
} from "./util.js";

const projectId = process.env["BLOCKFROST_PROJECT_ID"];
if (!projectId) {
  throw new Error("Missing blockfrost key");
}

let provider: Provider;
if (process.env["MAINNET"]) {
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

const skeyHex = process.env["SKEY_HEX"];
if (!skeyHex) {
  throw new Error("Missing skey");
}
let network: NetworkId;
if (process.env["MAINNET"]) {
  network = NetworkId.Mainnet;
} else {
  network = NetworkId.Testnet;
}
const wallet = new HotSingleWallet(Ed25519PrivateNormalKeyHex(skeyHex), network, provider);
const blaze = await Blaze.from(provider, wallet);

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
    console.log(pd.identifier.toString('hex'));
    if (pd.identifier.toString('hex') == poolIdent) {
      console.log("found pool");
      pool = knownPool;
    }
  }
  if (!pool) {
    throw new Error(`Couldn't find pool with ident: ${poolIdent}`);
  }
  return pool;
}

async function findChange(address: Core.Address, amount: bigint): Promise<Core.TransactionUnspentOutput> {
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

async function findChangeMany(address: Core.Address, amount: bigint, count: bigint): Promise<Core.TransactionUnspentOutput[]> {
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

interface BlueprintScript {
  hash: string,
  validator: string,
}

interface Blueprint {
  settingsSpend: BlueprintScript,
  poolSpend: BlueprintScript,
  poolManage: BlueprintScript,
}

function decodeBlueprint(blueprint: string): Blueprint {
  let bp: any = {};
  let o = JSON.parse(blueprint);
  for (let v of o.validators) {
    if (v.title == "settings.spend") {
      bp.settingsSpend = {
        hash: v.hash,
        validator: v.compiledCode,
      };
    }
    if (v.title == "pool.spend") {
      bp.poolSpend = {
        hash: v.hash,
        validator: v.compiledCode,
      };
    }
    if (v.title == "pool.manage") {
      bp.poolManage = {
        hash: v.hash,
        validator: v.compiledCode,
      };
    }
  }
  return bp as Blueprint;
}

async function buildUpdateFeeManager(args: any): Promise<Core.Transaction> {
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

  let myChange = await findChange(address, 20_000_000n);

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
    networkId: network,
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

function prepareUpdate(argv: any) {
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

async function signMessage(argv: any) {
  let key = skeyHex;
  if (key == undefined) {
    throw new Error(`signing key not configured`);
  }
  const signature = await ed.signAsync(argv.message, key);
  console.log("message: " + argv.message);
  console.log("signature: " + Buffer.from(signature).toString('hex'));
}

async function makeRedeemer(argv: any) {
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

async function updateFeeManager(argv: any) {
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

async function updatePoolStakeCredential(args: any, pool: Core.TransactionUnspentOutput, change: Core.TransactionUnspentOutput) {
  let bp = decodeBlueprint(fs.readFileSync(args.blueprint, "utf8"));
  let poolAddress = pool.output().address();

  let address = Core.addressFromBech32(args.address);

  let poolDatum = pool.output().datum()?.asInlineData();
  if (!poolDatum) {
    throw new Error("No pool datum");
  }

  const poolManageAddress = new Core.Address({
    type: Core.AddressType.RewardScript,
    networkId: network,
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

async function updateSinglePoolStakeCredential(argv: any) {
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
  let change = await findChange(address, 20_000_000n);
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

async function testAutoWithdraw(argv: any) {
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

  let poolAddress = new Core.Address({
    type: Core.AddressType.BasePaymentScriptStakeKey,
    networkId: NetworkId.Testnet,
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

  let options = {
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
  };

  const tx = await buildWithdrawPoolRewards(options);
  console.log(`Test tx: ${tx.toCbor()}`);
}

async function debugConditionedScoop(argv: any) {
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

  let poolScoopRedeemer = PlutusData.fromCbor(Core.HexBlob("d87a9fd8799f00009f9f01d87a8000ffffffff"));

  // a wallet with a null provider can still sign but other operations will fail
  //
  // in lucid, emulator implemented the provider interface. but apparently not
  // in blaze
  if (!skeyHex) {
    throw new Error("Missing skey");
  }
  let myWallet = new HotSingleWallet(Ed25519PrivateNormalKeyHex(skeyHex), network, new EmulatorProvider(emulator));
  console.log(`emulator: initialized`);
  let tx = new TxBuilder(emulator.params)
    .addInput(pool, poolScoopRedeemer)
    .addInput(change1)
    .provideCollateral([change2])
    .useEvaluator(emulator.evaluator)
    .addReferenceInput(poolScriptReference)
    .setChangeAddress(myAddr)
    .setNetworkId(network);
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

async function registerStakeAddress(argv: any) {
  let address = Core.addressFromBech32(argv.address);

  const cred = {
    type: Core.CredentialType.ScriptHash,
    hash: argv.stakeAddrHash,
  };
  const stakeAddress = new Core.Address({
    type: Core.AddressType.RewardScript,
    networkId: network,
    // See https://github.com/input-output-hk/cardano-js-sdk/blob/a1d85a290e9caed7e2c53ed46a0633e84b307458/packages/core/src/Cardano/Address/RewardAddress.ts#L117
    paymentPart: cred,
  });

  let change = await findChange(address, 20_000_000n);
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

async function updateAllPoolStakeCredentials(argv: any) {
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
  let change = await findChangeMany(address, 7_000_000n, argv.count);
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
  blueprint: any,
  treasuryAddress: Address,
  poolAddress: Address,
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
  console.log(`pool datum: ${datumCbor}`);
  let newPoolDatum = decodePoolDatum(decoder(fromHex(datumCbor)));
  console.log(`decoded pool datum: ${stringify(newPoolDatum)}`);
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
  console.log("toSpend: ");
  console.log(toSpend);

  // TODO: temporarily setting treasuryAmount to most of the withdrawnAmount for
  // compat with preview, where the allowance is just 1/10
  let treasuryAmount = 9n * withdrawnAmount / 10n + 1n;
  let withheld = withdrawnAmount - treasuryAmount;

  const poolManageRedeemer = HexBlob(withEncoderHex(encodePoolManageRedeemer, {
    tag: "WithdrawFees",
    amount: withdrawnAmount,
    treasuryOutput: 1n,
    poolInput: poolInputIndex,
  }));

  let poolSpendRedeemer = HexBlob(withEncoderHex(encodePoolSpendRedeemer, {
    tag: "Manage",
  }));
  console.log(`poolSpendRedeemer: ${poolSpendRedeemer}`);

  let updatedPoolDatum = PlutusData.fromCbor(HexBlob(withEncoderHex(encodePoolDatum, newPoolDatum)));

  const poolManageAddress = new Core.Address({
    type: Core.AddressType.RewardScript,
    networkId: network,
    // See https://github.com/input-output-hk/cardano-js-sdk/blob/a1d85a290e9caed7e2c53ed46a0633e84b307458/packages/core/src/Cardano/Address/RewardAddress.ts#L117
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: options.blueprint.poolManage.hash,
    },
  });

  const tx = options.blaze
    .newTransaction()
    .addInput(options.change)
    .addInput(targetPool, PlutusData.fromCbor(poolSpendRedeemer));

  //const tx = blaze
  //  .newTransaction()
  //  .addInput(options.change)
  //  .addInput(targetPool, PlutusData.fromCbor(poolSpendRedeemer));

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

  let newPoolValue = targetPool.output().amount();
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
  let completed = await tx.complete();
  return completed;
}

async function queryPools(poolAddress: string, needed: bigint) {
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

// This takes a *builder* as an argument to allow automatic retrying in cases
// where there is contention for one of the tx inputs.
async function submitAndAwaitWithRetry(blaze: Blaze<Provider, Wallet>, buildTx: () => Promise<Transaction>) {
  let confirmed = false;
  while (!confirmed) {
    let tx = await buildTx();
    let hash = await blaze.submitTransaction(tx);
    console.log(`Submitted (${hash})...`);
    confirmed = await blaze.provider.awaitTransactionConfirmation(hash, 60_000);
    if (confirmed) {
      console.log(`Confirmed ${hash}`);
    } else {
      console.log(`Couldn't confirm transaction ${hash}; retrying`);
    }
  }
}

async function autoWithdrawRewards(argv: any) {
  // 1. 'queryPools': Compute optimal set of pools to withdraw from:
  //   a. Query all withdrawable pools
  //   b. Sort by amount of withdrawable funds
  //   c. Select prefix that satisfies needed amount of funds, call the length of this prefix N
  // 2. 'findChangeMany': Provision N change utxos in our wallet
  // 3. For each pool, build and submit a withdrawal TX using the `i`th change utxo (disabling automatic change selection), retrying if the submission fails due to scooper contention (usually at least one of the withdrawals needs to be retried in practice).
  let todo = await queryPools(argv.poolAddress, BigInt(argv.needed));
  console.log(todo);

  let change = await findChangeMany(Core.addressFromBech32(argv.walletAddress), 10_000_000n, BigInt(todo.length));
  for (let c of change) {
    console.log({
      hash: c.input().transactionId(),
      index: c.input().index(),
    });
  }

  let bp = decodeBlueprint(fs.readFileSync(argv.blueprint, "utf8"));

  const settingsAddress = new Core.Address({
    type: Core.AddressType.EnterpriseScript,
    networkId: network,
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
  console.log(settingsDatumCbor);
  let settingsDatum = decodeSettingsDatum(decoder(fromHex(settingsDatumCbor)));

  let referenceData = fs.readFileSync(argv.references, "utf8");
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

  let totalWithdrawn = 0n;

  if (argv.forceSubmit) {
    const response = prompt("Do you really want to force submission of all transactions? (yes/no)");
    if (response != "yes") {
      console.log("Aborting");
      return;
    }
  }

  for (let i = 0; i < todo.length; i++) {
    let thisChange = change[i];
    let targetPool = todo[i].pool.utxo;
    let options = {
      blaze: blaze,
      provider: provider,
      settings: settings,
      change: thisChange,
      targetPool: todo[i].pool.ident.toString("hex"),
      signers: argv.signers,
      withdrawnAmount: todo[i].amount,
      remainingAmount: undefined,
      withheldAddress: Core.addressFromBech32(argv.withheldAddress),
      references: references,
      blueprint: bp,
      treasuryAddress: Core.Address.fromBytes(Core.HexBlob(settingsDatum.treasuryAddress.bytes(network))),
      poolAddress: Core.addressFromBech32(argv.poolAddress),
    };

    if (argv.forceSubmit) {
      await submitAndAwaitWithRetry(blaze, async () => {
        const tx = await buildWithdrawPoolRewards(options);
        await blaze.signTransaction(tx);
        return tx;
      });
    } else if (argv.submit) {
      const tx = await buildWithdrawPoolRewards(options);
      await blaze.signTransaction(tx);
      const response = prompt("Type 'submit' to submit");
      if (response == "submit") {
        await blaze.submitTransaction(tx);
        console.log("Submitted");
      }
    } else {
      const tx = await buildWithdrawPoolRewards(options);
      console.log(`Please sign and submit this transaction: ${tx.toCbor()}`);
    }
    totalWithdrawn += todo[i].amount;
    console.log(`Total withdrawn so far: ${totalWithdrawn}`);
  }
}

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
} else if (argv.registerStakeAddress) {
  await registerStakeAddress(argv);
} else if (argv.debugConditionedScoop) {
  await debugConditionedScoop(argv);
//} else if (argv.withdrawGenericStake) {
//  await withdrawGenericStake(argv);
} else if (argv.autoWithdrawRewards) {
  await autoWithdrawRewards(argv);
} else if (argv.testAutoWithdraw) {
  await testAutoWithdraw(argv);
}

process.exit(0);
