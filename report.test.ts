import { describe, it, expect } from "bun:test";
import * as crypto from "node:crypto";
import { Core } from "@blaze-cardano/sdk";
import { checkPayoutTotals, computePayments, decodeReportFromJson } from "./index.ts";
import { buildReport, parseScooperCsv, reportToJson, type ReportInput } from "./report.ts";

const SCOOPER_ADDRESSES = {
  ALICE: { new: "addr_alice" },
  BOB: { new: "addr_bob" },
  CAROL: { new: "addr_carol" },
};

const CSV = [
  "pub_key_hash,address,total_scoops,total_orders,total_protocol_fee,total_transaction_fee,total_num_mempool_orders",
  "aa,addr_alice,10,12,4000000000,100000000,3",
  "bb,addr_carol,20,25,6000000000,500000000,4",
  // A second row for the same scooper adds to the first
  "cc,addr_alice,5,6,0,200000000,1",
].join("\n");

function input(overrides: Partial<ReportInput> = {}): ReportInput {
  return {
    rows: parseScooperCsv(CSV),
    scooperAddresses: SCOOPER_ADDRESSES,
    extraScoopers: ["BOB"],
    delegatedScoopers: ["CAROL"],
    stakingRewards: { stake_a: 3_000_000_000n, stake_b: 2_000_000_000n },
    extraStableswapRevenue: 1_000_000_000n,
    ...overrides,
  };
}

describe("buildReport", () => {
  it("splits revenue between scoopers, yield farming and token holders", () => {
    let report = buildReport(input());

    // 10k ADA of protocol revenue, 5k of staking rewards, 1k from stableswaps
    expect(report.totalProtocolRevenue).toBe(10_000_000_000n);
    expect(report.totalRevenue).toBe(16_000_000_000n);
    expect(report.feesPaid).toEqual({ ALICE: 300_000_000n, CAROL: 500_000_000n, BOB: 0n });
    expect(report.totalFees).toBe(800_000_000n);
    // CAROL is delegated, so only ALICE and BOB get the flat reward
    expect(report.totalScoopers).toBe(2n);
    expect(report.payments).toEqual({
      // 50% is less than 20k ADA + 10%
      totalScooperPayout: 8_000_000_000n,
      yieldFarming: 5_600_000_000n,
      tokenHoldersFee: 1_600_000_000n,
      totalPayout: 15_200_000_000n,
      // Fees are reimbursed and the rest split between 2 scoopers
      flat: 3_600_000_000n,
      stakingRewardsNeeded: 5_000_000_000n,
      // What the staking rewards and stableswap revenue don't cover
      protocolFeesNeeded: 9_200_000_000n,
    });
  });

  it("caps the scooper payout at 20k ADA plus 10%", () => {
    let report = buildReport(input({ stakingRewards: { stake_a: 390_000_000_000n } }));
    expect(report.totalRevenue).toBe(401_000_000_000n);
    expect(report.payments.totalScooperPayout).toBe(20_000_000_000n + 40_100_000_000n);
  });

  it("needs no protocol fees when other revenue covers the payout", () => {
    let report = buildReport(input({ extraStableswapRevenue: 100_000_000_000n }));
    expect(report.payments.protocolFeesNeeded).toBe(0n);
  });

  it("refuses a row from an unknown scooper", () => {
    let rows = [...parseScooperCsv(CSV), { address: "addr_mallory", protocolFee: 1n, txFee: 1n }];
    expect(() => buildReport(input({ rows }))).toThrow(/addr_mallory/);
  });

  it("refuses a report with no scoopers to pay a flat reward", () => {
    expect(() => buildReport(input({ extraScoopers: [], delegatedScoopers: ["ALICE", "CAROL"] }))).toThrow(/No scoopers/);
  });
});

describe("parseScooperCsv", () => {
  it("refuses a row with too few columns", () => {
    expect(() => parseScooperCsv("header\naa,addr_alice,1")).toThrow(/row 1 has 3 columns/);
  });
});

describe("the report as read by the payout", () => {
  it("passes the payout's checks", () => {
    let report = decodeReportFromJson(reportToJson(buildReport(input())));
    let address = () => Core.Address.fromBytes(Core.HexBlob("60" + crypto.randomBytes(28).toString("hex")));
    let addresses = new Map(Object.keys(SCOOPER_ADDRESSES).map((name) => [name, address()]));

    let payments = computePayments(report, addresses);
    expect(() => checkPayoutTotals(report, payments)).not.toThrow();
    expect(report.payments.protocolFeesNeeded).toBe(9_200_000_000n);
  });
});
