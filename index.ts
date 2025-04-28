import * as fs from "node:fs";
import * as readline from "node:readline/promises";
import { stdin, stdout } from "node:process";
import {
  Datum,
  Ed25519PrivateNormalKeyHex,
  Hash32ByteBase16,
  HexBlob,
  NetworkId,
  PlutusData,
  PlutusV2Script,
  PlutusV3Script,
  Script,
  TransactionId,
  TransactionInput,
  Value,
} from "@blaze-cardano/core";
import { HotSingleWallet, Core, Blaze, Blockfrost } from "@blaze-cardano/sdk";
import { TxBuilder } from "@blaze-cardano/tx";
import { Emulator } from "@blaze-cardano/emulator";
import * as ed from "@noble/ed25519";
import minimist from "minimist";
import {
  decoder,
  decodeNewFees,
  decodeNewFeeManager,
  decodePoolDatum,
  encoder,
  withEncoder,
  withEncoderHex,
  encodePoolDatum,
  encodePoolSpendRedeemer,
  encodePoolManageRedeemer,
  encodeConvenienceFeeManagerRedeemer,
  encodeNewFees,
  encodeNewFeeManager,
} from "./codec.js";
import {
  fromHex,
  stringify,
} from "./util.js";

const projectId = process.env["BLOCKFROST_PROJECT_ID"];
if (!projectId) {
  throw new Error("Missing blockfrost key");
}

let provider;
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
let network;
if (process.env["MAINNET"]) {
  network = NetworkId.Mainnet;
} else {
  network = NetworkId.Testnet;
}
const wallet = new HotSingleWallet(Ed25519PrivateNormalKeyHex(skeyHex), network, provider);
const blaze = await Blaze.from(provider, wallet);

async function findPoolByIdent(poolAddress: Core.Address, poolIdent: string): Promise<Core.TransactionUnspentOutput | null> {
  let pool = null;
  // the pool policy is the same as the spending validator hash
  let poolPolicy = poolAddress.getProps().paymentPart.hash;
  let poolNft = poolPolicy + "000de140" + poolIdent;
  let knownPool = await provider.getUnspentOutputByNFT(poolNft);
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
  return pool;
}

async function findChange(address: Core.Address, amount: bigint) {
  const utxos = await provider.getUnspentOutputs(address);
  for (const utxo of utxos) {
    // Skip utxos with assets
    if (utxo.output().amount().multiasset().size > 0) {
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
}

async function findChangeMany(address: Core.Address, amount: bigint, count: bigint) {
  const utxos = await provider.getUnspentOutputs(address);
  let change = [];
  for (const utxo of utxos) {
    // Skip utxos with assets
    if (utxo.output().amount().multiasset().size > 0) {
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



function compareUtxo(a: any, b: any): number {
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

function decodeBlueprint(blueprint: string): any {
  let bp: any = {};
  let o = JSON.parse(blueprint);
  for (let v of o.validators) {
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
  return bp;
}

async function buildUpdateFeeManager(args: any): Promise<Core.Transaction> {
  let bp = decodeBlueprint(fs.readFileSync(args.blueprint, "utf8"));
  let poolAddress = Core.addressFromBech32(args.poolAddress);

  let address = Core.addressFromBech32(args.address);

  let poolIdent = args.poolIdent;
  let pool = await findPoolByIdent(poolAddress, poolIdent);

  if (!pool) {
    throw new Error("can't find pool");
  }

  let poolDatum = pool.output().datum();

  if (!poolDatum) {
    throw new Error("no pool datum");
  }

  // Update pool datum in output
  let poolDatumDecoded = decodePoolDatum(decoder(fromHex(poolDatum.toCore().cbor)));
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
      hash: bp.poolManage.hash,
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

function parseSignatures(signatures) {
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

function prepareUpdate(argv) {
  if (argv.updateFees) {
    let updateObject = {
      validRange: {
        lowerBound: { boundType: { tag: "NegativeInfinity" }, isInclusive: true },
        upperBound: { boundType: { tag: "PositiveInfinity" }, isInclusive: true },
      },
      newBidFees: BigInt(argv.newBidFees),
      newAskFees: BigInt(argv.newAskFees),
    };
    console.log(withEncoderHex(encodeNewFees, updateObject));
  } else if (argv.updateManager) {
    let updateObject = {
      validRange: {
        lowerBound: { boundType: { tag: "NegativeInfinity" }, isInclusive: true },
        upperBound: { boundType: { tag: "PositiveInfinity" }, isInclusive: true },
      },
      feeManager: JSON.parse(argv.feeManager),
    };
    console.log(withEncoderHex(encodeNewFeeManager, updateObject));
  }
}

async function signMessage(argv) {
  const signature = await ed.signAsync(argv.message, skeyHex);
  console.log("message: " + argv.message);
  console.log("signature: " + Buffer.from(signature).toString('hex'));
}

async function makeRedeemer(argv) {
  if (argv.updateFees) {
    let updateObject = decodeNewFees(decoder(fromHex(argv.updateObject)));
    let signatures = parseSignatures(argv.signatures);
    let redeemer = {
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
    let redeemer = {
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

async function updateFeeManager(argv) {
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

async function updatePoolStakeCredential(args, pool, change) {
  let bp = decodeBlueprint(fs.readFileSync(args.blueprint, "utf8"));
  let poolAddress = pool.output().address();

  let address = Core.addressFromBech32(args.address);

  const poolManageAddress = new Core.Address({
    type: Core.AddressType.RewardScript,
    networkId: network,
    // See https://github.com/input-output-hk/cardano-js-sdk/blob/a1d85a290e9caed7e2c53ed46a0633e84b307458/packages/core/src/Cardano/Address/RewardAddress.ts#L117
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: bp.poolManage.hash,
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
  let references = await provider.resolveUnspentOutputs(referenceRefs);

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
    .lockAssets(newPoolAddress, pool.output().amount(), pool.output().datum())

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
      }
    })

  for (let reference of references) {
    tx = tx.addReferenceInput(reference);
  }

  tx = tx.provideScript(poolManageScript);

  let completed = await tx.complete();
  return completed;
}

async function updateSinglePoolStakeCredential(argv) {
  let address = Core.addressFromBech32(argv.address);
  let poolAddress = Core.addressFromBech32(argv.poolAddress);

  let pool = null;
  // the pool policy is the same as the spending validator hash
  let poolPolicy = poolAddress.getProps().paymentPart.hash;
  let poolNft = poolPolicy + "000de140" + argv.poolIdent;
  let knownPool = await provider.getUnspentOutputByNFT(poolNft);
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

function getPoolDatum(pool) {
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
function poolTVL(pool) {
  return pool.output().amount().coin() * 2n;
}

function txref(utxo) {
  let txid = utxo.input().transactionId();
  let txix = utxo.input().index();
  return `${txid}#${txix}`;
}

function comparePoolTVL(a, b) {
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

async function debugConditionedScoop(argv) {
  let myAddr = Core.Address.fromBech32("addr_test1vqp4mmnx647vyutfwugav0yvxhl6pdkyg69x4xqzfl4vwwck92a9t");
  let poolAddr = Core.Address.fromBech32("addr_test1xzly6g2kvwgfhdvntwfrct0kz9erfqyntw68yt2lz54kg6kvy7vq4p2hl6wm9jdvpgn80ax3xpkm7yrgnxphtrct3klqnkjjzt");
  let change1 = new Core.TransactionUnspentOutput(
    new Core.TransactionInput(
      Core.TransactionId("00".repeat(32)),
      0n
    ),
    new Core.TransactionOutput(
      myAddr,
      new Core.Value(
        100_000_000n,
      ),
    )
  );
  let genesisOutputs = [change1.output()];
  let emulator = new Emulator(genesisOutputs);

  emulator.addUtxo(
    new Core.TransactionUnspentOutput(
      new Core.TransactionInput(
        Core.TransactionId("4135f635b4f26859231c696699593781e04ffb8eef4576c9917694dcad61693b"),
        0n
      ),
      new Core.TransactionOutput(
        poolAddr,
        new Core.Value(
          13_000_000n,
          new Map([
            ["99b071ce8580d6a3a11b4902145adb8bfd0d2a03935af8cf66403e15524245525259", 100000],
            ["be4d215663909bb5935b923c2df611723480935bb4722d5f152b646a000de140a4745a3d72cd31eba160563dbaa3538b574b21cb4a08aef57e18f457", 1],
          ])
        ),
      )
    )
  );

  // a wallet with a null provider can still sign but other operations will fail
  // in lucid, emulator implemented the provider interface...
  let myWallet = new HotSingleWallet(Ed25519PrivateNormalKeyHex(skeyHex), network, null);
  console.log(`emulator: initialized`);
  let tx = new TxBuilder(emulator.params)
    .addInput(change1)
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

async function registerStakeAddress(argv) {
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

    .addRegisterStake(new Core.Credential(cred))

    //.useCoinSelector((inputs, dearth) => {
    //  return {
    //    selectedInputs: [],
    //    selectedValue: new Value(0n),
    //    inputs: [],
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

async function updateAllPoolStakeCredentials(argv) {
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
}

process.exit(0);
