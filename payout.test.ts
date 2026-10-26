import { describe, it, expect, beforeEach } from "bun:test";
import * as crypto from "node:crypto";
import { Core } from "@blaze-cardano/sdk";
import {
  checkPayoutTotals,
  computePayments,
  decodeReportFromJson,
  displayPreviousMonth,
  payout,
  type BuildPayoutOptions,
  type Report,
} from "./index.ts";
import { STABLE_TOKEN, makeWorld, type World } from "./testFixtures.ts";

// These tests build the real payout transaction against an emulated ledger and
// check that it pays exactly what the report says, to exactly whom it says.

// Stands in for SUNDAE
const SUNDAE = STABLE_TOKEN;

function randomAddress(): Core.Address {
  // Testnet enterprise address with a random key hash
  return Core.Address.fromBytes(Core.HexBlob("60" + crypto.randomBytes(28).toString("hex")));
}

const SCOOPERS = ["alice", "bob", "carol"];
const ADDRESSES = new Map(SCOOPERS.map((name) => [name, randomAddress()]));

function reportJson(overrides: Record<string, any> = {}): string {
  return JSON.stringify({
    feesPaid: { alice: 5_000_000, bob: 7_000_000, carol: 1_500_000 },
    totalScoopers: 3,
    delegatedScoopers: ["carol"],
    payments: {
      tokenHoldersFee: 20_000_000,
      yieldFarming: 70_000_000,
      flat: 2_000_000,
      // Scoopers get 17.5 ADA
      totalPayout: 107_500_000,
      protocolFeesNeeded: 45_000_000,
    },
    ...overrides,
  });
}

function fund(world: World, asset: string, amount: bigint) {
  let output = new Core.TransactionOutput(world.wallet, new Core.Value(2_000_000n, new Map([[Core.AssetId(asset), amount]])));
  let input = new Core.TransactionInput(Core.TransactionId(crypto.randomBytes(32).toString("hex")), 0n);
  world.emulator.addUtxo(new Core.TransactionUnspentOutput(input, output));
}

// Plain wallet utxos, as collectChangeMa would pick
function walletUtxos(world: World): Core.TransactionUnspentOutput[] {
  return world.emulator.utxos().filter((u) =>
    u.output().address().toBytes() == world.wallet.toBytes() && !u.output().scriptRef() && !u.output().datum());
}

// Lovelace paid to each address, keyed by address bytes
function paidTo(tx: Core.Transaction): Map<string, Core.Value> {
  let paid = new Map();
  for (let output of tx.body().outputs()) {
    paid.set(output.address().toBytes(), output.amount());
  }
  return paid;
}

describe("payout", () => {
  let world: World;
  let report: Report;
  let tokenHolders: Core.Address;
  let yieldFarming: Core.Address;

  beforeEach(async () => {
    world = await makeWorld();
    fund(world, SUNDAE, 1_000_000_000n);
    report = decodeReportFromJson(reportJson());
    tokenHolders = randomAddress();
    yieldFarming = randomAddress();
  });

  function runPayout(overrides: Partial<BuildPayoutOptions> = {}) {
    return payout({
      blaze: world.blaze,
      changeUtxos: walletUtxos(world),
      report,
      tokenHoldersDestination: tokenHolders,
      yieldFarmingDestination: yieldFarming,
      yieldFarmingAmount: 123_000_000n,
      scooperPayments: computePayments(report, ADDRESSES),
      approve: async () => true,
      addresses: ADDRESSES,
      txLogDir: "",
      sundaeAssetId: SUNDAE,
      month: "2026-09",
      ...overrides,
    });
  }

  it("pays scoopers, token holders and yield farming, and returns the rest", async () => {
    let before = walletUtxos(world);
    let tx = await runPayout();

    expect(world.provider.landed.has(tx.getId())).toBe(true);
    let paid = paidTo(tx);
    // Fees plus the flat reward, except for delegated scoopers
    expect(paid.get(ADDRESSES.get("alice")!.toBytes())!.coin()).toBe(7_000_000n);
    expect(paid.get(ADDRESSES.get("bob")!.toBytes())!.coin()).toBe(9_000_000n);
    expect(paid.get(ADDRESSES.get("carol")!.toBytes())!.coin()).toBe(1_500_000n);
    expect(paid.get(tokenHolders.toBytes())!.coin()).toBe(20_000_000n);
    let farm = paid.get(yieldFarming.toBytes())!;
    expect(farm.coin()).toBe(2_000_000n);
    expect(farm.multiasset()?.get(SUNDAE)).toBe(123_000_000n);
    // Five payments and the change, with nothing paid anywhere else
    expect(tx.body().outputs().length).toBe(6);

    // Everything else, including the rest of the SUNDAE, comes back
    let spentCoin = before.reduce((n, u) => n + u.output().amount().coin(), 0n);
    let change = paid.get(world.wallet.toBytes())!;
    expect(change.coin()).toBe(spentCoin - 7_000_000n - 9_000_000n - 1_500_000n - 20_000_000n - 2_000_000n - tx.body().fee());
    expect(change.multiasset()?.get(SUNDAE)).toBe(1_000_000_000n - 123_000_000n);
  });

  it("records the month and per-scooper breakdown in the metadata", async () => {
    let tx = await runPayout();

    let metadata = tx.auxiliaryData()!.toCore().blob!;
    expect(metadata.get(674n)).toEqual(new Map([["msg", ["Sundae Revenue 2026-09"]]]));
    let breakdown = metadata.get(73115n) as Map<Uint8Array, Map<string, bigint>>;
    let byHash = new Map([...breakdown].map(([hash, entry]) => [Buffer.from(hash).toString("hex"), entry]));
    expect(byHash.size).toBe(3);
    let carol = ADDRESSES.get("carol")!.getProps().paymentPart!.hash;
    expect(byHash.get(carol)).toEqual(new Map([["fees", 1_500_000n], ["rewards", 0n]]));
    let bob = ADDRESSES.get("bob")!.getProps().paymentPart!.hash;
    expect(byHash.get(bob)).toEqual(new Map([["fees", 7_000_000n], ["rewards", 2_000_000n]]));
  });

  it("refuses a payment below min-ADA rather than overpaying it", async () => {
    report = decodeReportFromJson(reportJson({ feesPaid: { alice: 5_000_000, bob: 7_000_000, carol: 300_000 } }));
    await expect(runPayout()).rejects.toThrow(/would pay \d+ instead of 300000/);
    expect(world.provider.submissions.length).toBe(0);
  });

  it("builds without submitting in a dry run", async () => {
    let tx = await runPayout({ approve: undefined });
    expect(tx.body().outputs().length).toBe(6);
    expect(world.provider.submissions.length).toBe(0);
  });

  it("stops when the operator declines", async () => {
    await expect(runPayout({ approve: async () => false })).rejects.toThrow(/Aborted/);
    expect(world.provider.submissions.length).toBe(0);
  });
});

describe("computePayments", () => {
  it("refuses a scooper with no known address", () => {
    let report = decodeReportFromJson(reportJson({ feesPaid: { alice: 1, mallory: 1 } }));
    expect(() => computePayments(report, ADDRESSES)).toThrow(/mallory/);
  });
});

describe("checkPayoutTotals", () => {
  function check(payments: Record<string, number>) {
    let obj = JSON.parse(reportJson());
    obj.payments = { ...obj.payments, ...payments };
    let report = decodeReportFromJson(JSON.stringify(obj));
    checkPayoutTotals(report, computePayments(report, ADDRESSES));
  }

  it("accepts a report whose payments add up", () => {
    check({});
  });

  it("allows for each share being rounded", () => {
    check({ yieldFarming: 70_000_003, totalPayout: 107_500_002 });
  });

  it("refuses a report with payments it doesn't make", () => {
    expect(() => check({ sundaeMiscFee: 1_000_000, totalPayout: 108_500_000 })).toThrow(/sundaeMiscFee/);
  });

  it("refuses a report whose payments don't add up to the total", () => {
    expect(() => check({ totalPayout: 108_500_000 })).toThrow(/add up to 107500000/);
  });

  it("refuses a report that isn't split 35:10", () => {
    expect(() => check({ yieldFarming: 60_000_000, totalPayout: 97_500_000 })).toThrow(/35:10/);
  });
});

describe("decodeReportFromJson", () => {
  it("says which payment field is missing", () => {
    let obj = JSON.parse(reportJson());
    delete obj.payments.tokenHoldersFee;
    expect(() => decodeReportFromJson(JSON.stringify(obj))).toThrow("Missing 'payments.tokenHoldersFee'");
  });
});

describe("displayPreviousMonth", () => {
  it("labels the month before the given date", () => {
    expect(displayPreviousMonth(new Date(2026, 9, 3))).toBe("2026-09");
    expect(displayPreviousMonth(new Date(2026, 0, 3))).toBe("2025-12");
  });
});
