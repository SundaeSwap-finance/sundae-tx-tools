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
import minimist from "minimist";
import {
  decoder,
  decodePoolDatum,
  encoder,
  withEncoder,
  withEncoderHex,
  encodePoolSpendRedeemer,
  encodePoolManageRedeemer,
  encodeConvenienceFeeManagerRedeemer,
} from "./codec.js";
import {
  fromHex,
  stringify,
} from "./util.js";

const projectId = process.env["BLOCKFROST_PROJECT_ID"];
if (!projectId) {
  throw new Error("Missing blockfrost key");
}

const provider = new Blockfrost({
  network: "cardano-preview",
  projectId,
});

const skeyHex = process.env["SKEY_HEX"];
if (!skeyHex) {
  throw new Error("Missing skey");
}
const wallet = new HotSingleWallet(Ed25519PrivateNormalKeyHex(skeyHex), NetworkId.Testnet, provider);
const blaze = await Blaze.from(provider, wallet);

async function findPoolByIdent(poolAddress: Core.Address, poolIdent: string): Promise<Core.TransactionUnspentOutput | null> {
  let pool = null;
  let knownPools = await provider.getUnspentOutputs(poolAddress);
  for (let knownPool of knownPools) {
    let datum = knownPool.output().datum();
    if (!datum) {
      continue;
    }
    let datumCbor = (datum.toCore() as any).cbor;
    let pd = decodePoolDatum(decoder(fromHex(datumCbor)));
    console.log(pd.identifier.toString('hex'));
    if (pd.identifier.toString('hex') == poolIdent) {
      console.log("found pool");
      pool = knownPool;
      break;
    }
  }
  return pool;
}

async function findChange(address: Core.Address, amount: bigint) {
  const utxos = await provider.getUnspentOutputs(address);
  for (const utxo of utxos) {
    const utxoRef = `${utxo.input().transactionId()}#${utxo.input().index()}`;
    console.log(utxoRef);
    if (utxo.output().amount().coin() >= amount) {
      console.log("found suitable change");
      return utxo;
    }
  }
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

  // "ba228444515fbefd2c8725338e49589f206c7f18a33e002b157aac3c";
  let poolIdent = args.poolIdent;
  let pool = await findPoolByIdent(poolAddress, poolIdent);

  if (!pool) {
    throw new Error("can't find pool");
  }
  
  let poolDatum = pool.output().datum();

  if (!poolDatum) {
    throw new Error("no pool datum");
  }

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

  // "stake_test17qyzjcwjsw8ju4tw058ejq6f08w2au0t46zaudeqkmdvsgsl0km99"
  const poolManageAddress = new Core.Address({
    type: Core.AddressType.RewardScript,
    networkId: args.mainnet ? Core.NetworkId.Mainnet : Core.NetworkId.Testnet,
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

    // Pay the input pool as an output, unchanged.
    .lockAssets(poolAddress, pool.output().amount(), poolDatum as unknown as Datum)

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

let argv = minimist(process.argv.slice(2));
if (argv.buildUpdateFeeManager) {
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

process.exit(0);
