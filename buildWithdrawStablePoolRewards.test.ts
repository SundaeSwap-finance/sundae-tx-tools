import { describe, it, expect, beforeAll } from "bun:test";
import * as fs from "node:fs";
import {
  Address,
  AssetId,
  ExUnits,
  Hash28ByteBase16,
  HexBlob,
  NetworkId,
  PlutusData,
  PlutusV2Script,
  Redeemer,
  Redeemers,
  Script,
  Transaction,
  TransactionId,
  TransactionInput,
  TransactionOutput,
  TransactionUnspentOutput,
  Value,
  hardCodedProtocolParams,
  type Evaluator,
} from "@blaze-cardano/core";
import { Core } from "@blaze-cardano/sdk";
import { Emulator } from "@blaze-cardano/emulator";
import {
  buildWithdrawStablePoolRewards,
  decodeBlueprint,
  type Blueprint,
} from "./index.ts";
import {
  withEncoderHex,
  encodeStablePoolDatum,
} from "./codec.ts";
import { fromHex } from "./util.ts";

// ---- Test data constants ----

// Stable pool identifier from the stableswaps expectations fixture
const POOL_IDENT = "82f70fd1663b2b6f4250d6054fe4cac8c815d9eef8b38f68bbe22c92";

// Token B: tINDY on preview
const TINDY_POLICY = "fa3eff2047fdf9293c5feef4dc85ce58097ea1c6da4845a351535183";
const TINDY_TOKEN = "74494e4459"; // "tINDY" in hex
const TINDY_ASSET_ID = AssetId(`${TINDY_POLICY}.${TINDY_TOKEN}`);

// A signer key hash (32 bytes of zeros for testing)
const TEST_SIGNER = "0".repeat(56);

// A recipient address for treasury/withheld: a simple enterprise key address on testnet
// Payment key hash = 32 zero bytes → addr_test1vq...
const RECIPIENT_ADDR_HEX = "60" + "00".repeat(28);

// ---- No-op script evaluator ----
// Returns the transaction's existing redeemers with preset execution units
// so TxBuilder.complete() can compute fees without actually running UPLC.
const noopEvaluator: Evaluator = async (tx: Transaction, _: TransactionUnspentOutput[]): Promise<Redeemers> => {
  const existing = tx.witnessSet().redeemers();
  if (!existing) {
    return Redeemers.fromCore([]);
  }
  existing.values().forEach((r: Redeemer) => {
    r.setExUnits(new ExUnits(1_000_000n, 500_000_000n));
  });
  return existing;
};

// ---- Blueprint loading ----
const blueprintJson = fs.readFileSync(
  new URL("./preview.blueprint.json", import.meta.url),
  "utf8",
);
const blueprint: Blueprint = decodeBlueprint(blueprintJson);

// ---- Helper: create a TransactionUnspentOutput ----
function makeUtxo(
  txHash: string,
  index: bigint,
  output: TransactionOutput,
): TransactionUnspentOutput {
  return new TransactionUnspentOutput(
    new TransactionInput(TransactionId(txHash), index),
    output,
  );
}

// ---- Helper: build pool address from pool.spend script hash ----
function poolAddress(): Address {
  return new Address({
    type: Core.AddressType.EnterpriseScript,
    networkId: NetworkId.Testnet,
    paymentPart: {
      type: Core.CredentialType.ScriptHash,
      hash: Hash28ByteBase16(blueprint.poolSpend.hash),
    },
  });
}

// ---- Helper: build a basic enterprise key address ----
function keyAddress(keyHashHex: string): Address {
  return Address.fromBytes(HexBlob("60" + keyHashHex));
}

// ---- Helper: build stable pool datum CBOR ----
function makeStablePoolDatum(protocolFees: [bigint, bigint, bigint]): PlutusData {
  const datumHex = withEncoderHex(encodeStablePoolDatum, {
    identifier: fromHex(POOL_IDENT),
    assetPair: [
      [Buffer.alloc(0), Buffer.alloc(0)],                   // assetA = ADA
      [fromHex(TINDY_POLICY), fromHex(TINDY_TOKEN)],       // assetB = tINDY
    ],
    circulatingLp: 40_000_000n,
    lpFeeBasisPoints: [5n, 5n],
    protocolFeeBasisPoints: [5n, 5n],
    feeManager: null,
    marketOpen: 0n,
    protocolFees,
    linearAmplification: 200n,
    sumInvariant: 40_000_000_000_000_000_000n,
    linearAmplificationManager: null,
  });
  return PlutusData.fromCbor(HexBlob(datumHex));
}

// ---- Test ----

describe("buildWithdrawStablePoolRewards", () => {
  let emulator: Emulator;

  // Pool NFT asset ID = pool.spend hash + "000de140" + pool ident
  const poolNftAssetId = AssetId(
    blueprint.poolSpend.hash + "000de140" + POOL_IDENT,
  );

  // Fee amounts: pool has 5 ADA flat fees and 3M tINDY token fees accumulated
  const POOL_PROTOCOL_FEES: [bigint, bigint, bigint] = [5_000_000n, 0n, 3_000_000n];
  const WITHDRAW_FLAT = 4_000_000n;   // withdraw 4 ADA flat fee
  const WITHDRAW_A = 0n;               // assetA = ADA, 0 separate bucket
  const WITHDRAW_B = 2_000_000n;       // withdraw 2M tINDY

  // Pool UTxO: 20 ADA + pool NFT + 10M tINDY liquidity + accumulated fees
  const POOL_COIN = 20_000_000n;
  const POOL_TINDY = 13_000_000n; // liquidity + protocol fees

  const poolDatum = makeStablePoolDatum(POOL_PROTOCOL_FEES);

  // Pool spend script (as a reference script UTxO)
  const poolSpendScript = Script.newPlutusV2Script(
    new PlutusV2Script(HexBlob(blueprint.poolSpend.validator)),
  );

  // Pool manage script (withdrawal validator), also as a reference script UTxO
  const poolManageScript = Script.newPlutusV2Script(
    new PlutusV2Script(HexBlob(blueprint.poolManage.validator)),
  );

  beforeAll(() => {
    // Pool UTxO at the pool script address
    const poolOutput = new TransactionOutput(poolAddress(), new Value(POOL_COIN, new Map([
      [poolNftAssetId, 1n],
      [TINDY_ASSET_ID, POOL_TINDY],
    ])));
    poolOutput.setDatum(Core.Datum.newInlineData(poolDatum));

    // Reference UTxO carrying the pool.spend script
    const refOutput = new TransactionOutput(
      Address.fromBytes(HexBlob("60" + "aa".repeat(28))), // arbitrary address
      new Value(2_000_000n),
    );
    refOutput.setScriptRef(poolSpendScript);

    const manageRefOutput = new TransactionOutput(
      Address.fromBytes(HexBlob("60" + "aa".repeat(28))),
      new Value(2_000_000n),
    );
    manageRefOutput.setScriptRef(poolManageScript);

    // Settings UTxO (just needs to exist as a reference input)
    const settingsOutput = new TransactionOutput(
      Address.fromBytes(HexBlob("60" + "bb".repeat(28))),
      new Value(2_000_000n),
    );

    emulator = new Emulator(
      [poolOutput, refOutput, manageRefOutput, settingsOutput],
      hardCodedProtocolParams,
      { evaluator: noopEvaluator },
    );

    // Register a wallet with enough ADA for fees and collateral
    emulator.register("scooper", new Value(50_000_000n));
  });

  it("builds a valid fee-withdrawal transaction for a stableswap pool", async () => {
    await emulator.as("scooper", async (blaze, scoopeAddress) => {
      // Fetch the change UTxO from the scooper wallet
      const walletUtxos = await blaze.wallet.getUnspentOutputs();
      expect(walletUtxos.length).toBeGreaterThan(0);
      const changeUtxo = walletUtxos[0];

      // Fetch the reference UTxO (script ref) and settings UTxO from the emulator
      const allUtxos = emulator.utxos();
      const refUtxos = allUtxos.filter((u) => u.output().scriptRef() != null);
      expect(refUtxos.length).toBe(2);
      const settingsUtxo = allUtxos.find((u) =>
        u.output().amount().coin() === 2_000_000n &&
        u.output().scriptRef() == null &&
        u.output().datum() == null &&
        u.output().address().toBytes() !== poolAddress().toBytes(),
      );
      expect(settingsUtxo).toBeDefined();

      const treasuryAddr = keyAddress("cc".repeat(28));
      const withheldAddr = keyAddress("dd".repeat(28));

      const completed = await buildWithdrawStablePoolRewards({
        blaze,
        provider: blaze.provider,
        settings: settingsUtxo!,
        change: changeUtxo,
        targetPool: POOL_IDENT,
        signers: TEST_SIGNER,
        withdrawnAmountFlat: WITHDRAW_FLAT,
        withdrawnAmountA: WITHDRAW_A,
        withdrawnAmountB: WITHDRAW_B,
        remainingAmountFlat: undefined,
        remainingAmountA: undefined,
        remainingAmountB: undefined,
        withheldAddress: withheldAddr,
        references: refUtxos,
        blueprint,
        treasuryAddress: treasuryAddr,
        poolAddress: poolAddress(),
        allowance: { numerator: 1n, denominator: 2n },
        treasuryAmountFlat: undefined,
        treasuryAmountA: undefined,
        treasuryAmountB: undefined,
        txLogDir: "/tmp",
      });

      expect(completed).toBeDefined();

      // Verify the transaction has outputs going to treasury and withheld addresses
      const outputs = completed.body().outputs().map((o) => o.toCore());

      const poolOutput = outputs[0];
      expect(poolOutput.address === poolAddress().toBech32());

      const treasuryOutput = outputs[1];
      expect(treasuryOutput.address === treasuryAddr.toBech32());

      const walletOutput = outputs[2];
      expect(walletOutput.address == withheldAddr.toBech32());

      // Treasury and wallet should receive withdrawn amount according to
      // allowance
      const treasuryOutputAfter = BigInt(treasuryOutput!.value.coins);
      expect(treasuryOutputAfter).toBe(WITHDRAW_FLAT / 2n);
      const walletOutputAfter = BigInt(walletOutput!.value.coins);
      expect(walletOutputAfter).toBe(WITHDRAW_FLAT / 2n);

      // Pool output should have reduced ADA (flat fee + assetA fee withdrawn)
      const poolCoinAfter = BigInt(poolOutput!.value.coins);
      expect(poolCoinAfter).toBe(POOL_COIN - WITHDRAW_FLAT - WITHDRAW_A);

      // Pool output should have reduced tINDY
      const poolTindyAfter = poolOutput!.value.assets?.get(TINDY_ASSET_ID) ?? 0n;
      expect(poolTindyAfter).toBe(POOL_TINDY - WITHDRAW_B);
    });
  });
});
