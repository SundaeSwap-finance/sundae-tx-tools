import { describe, it, expect, beforeEach } from "bun:test";
import * as crypto from "node:crypto";
import { Core } from "@blaze-cardano/sdk";
import { EContractVersion } from "@sundaeswap/core";
import { buyWithAda, convertAssetsToAda, type BuyWithAdaOptions, type ConvertAssetsOptions } from "./index.ts";
import {
  FakeQueryProvider,
  FakeScooper,
  STABLE_FEES,
  STABLE_ORDER_HASH,
  STABLE_TOKEN,
  makePoolData,
  makeWorld,
  runAutoWithdraw,
  sdkAssetId,
  type World,
} from "./testFixtures.ts";

// These tests run the real asset conversion against an emulated ledger, with a
// fake scooper that fills the swap orders it places. The scooper decodes each
// order's datum and pays out to the destination it names, so these also check
// that the orders are well formed.

// Another token, which only trades against STABLE_TOKEN
const OTHER_TOKEN = Core.AssetId("de".repeat(28) + "4f54484552"); // "OTHER"

function ident(): string {
  return crypto.randomBytes(28).toString("hex");
}

// What a constant product pool with a 0.3% fee pays for an offer
function swapOutput(reserveIn: bigint, reserveOut: bigint, offer: bigint): bigint {
  return reserveOut * offer * 9_970n / (reserveIn * 10_000n + offer * 9_970n);
}

interface Market {
  query: FakeQueryProvider,
  scooper: FakeScooper,
  preferredPools: Record<string, { pool: string }>,
}

// ADA/STABLE_TOKEN at 2 ADA per token, and STABLE_TOKEN/OTHER_TOKEN at 1:1
function makeMarket(world: World, stableTokenPoolVersion = EContractVersion.V3): Market {
  let query = new FakeQueryProvider();
  let adaPool = makePoolData(ident(), "", STABLE_TOKEN, 2_000_000_000n, 1_000_000_000n, stableTokenPoolVersion);
  let otherPool = makePoolData(ident(), STABLE_TOKEN, OTHER_TOKEN, 1_000_000_000n, 1_000_000_000n);
  query.addPool(adaPool);
  query.addPool(otherPool);
  return {
    query,
    scooper: new FakeScooper(world.emulator, query),
    preferredPools: {
      [STABLE_TOKEN]: { pool: adaPool.ident },
      [OTHER_TOKEN]: { pool: otherPool.ident },
    },
  };
}

// Pays the wallet some tokens, as a withdrawal would
function fund(world: World, asset: string, amount: bigint) {
  let output = new Core.TransactionOutput(world.wallet, new Core.Value(2_000_000n, new Map([[Core.AssetId(asset), amount]])));
  let input = new Core.TransactionInput(Core.TransactionId(crypto.randomBytes(32).toString("hex")), 0n);
  world.emulator.addUtxo(new Core.TransactionUnspentOutput(input, output));
}

function walletBalance(world: World, asset: string): bigint {
  let total = 0n;
  for (let utxo of world.emulator.utxos()) {
    if (utxo.output().address().toBytes() == world.wallet.toBytes()) {
      total += utxo.output().amount().multiasset()?.get(Core.AssetId(asset)) ?? 0n;
    }
  }
  return total;
}

function runConvert(world: World, market: Market, assets: Record<string, string>, overrides: Partial<ConvertAssetsOptions> = {}) {
  return convertAssetsToAda({
    blaze: world.blaze,
    provider: world.provider,
    queryProvider: market.query,
    walletAddress: world.wallet,
    preferredPools: market.preferredPools,
    assets,
    minSwapReturn: 1n,
    approve: async () => true,
    confirmationTimeoutMs: 0,
    pollIntervalMs: 0,
    maxPolls: 10,
    // Time passing between checks for settled orders is when the scooper acts
    sleep: async () => market.scooper.scoop(),
    ...overrides,
  });
}

describe("convertAssetsToAda", () => {
  let world: World;
  let market: Market;

  beforeEach(async () => {
    world = await makeWorld("v3");
    market = makeMarket(world);
  });

  it("swaps a token to ada and reports the total ada, net of fees", async () => {
    fund(world, STABLE_TOKEN, 3_000_000n);
    let total = await runConvert(world, market, { "": "5000000", [STABLE_TOKEN]: "3000000" });

    let received = swapOutput(1_000_000_000n, 2_000_000_000n, 3_000_000n);
    expect(market.scooper.filled.length).toBe(1);
    expect(market.scooper.filled[0].received).toEqual(["ada.lovelace", received]);
    // The ada given plus the swap's proceeds
    expect(total).toBe(5_000_000n + received - market.scooper.protocolFee);
    expect(walletBalance(world, STABLE_TOKEN)).toBe(0n);
  });

  it("swaps tokens that share utxos, as a stable pool withdrawal pays them", async () => {
    // A second token with its own ada pool, at 1 ADA per token
    const PAIRED_TOKEN = Core.AssetId("ef".repeat(28) + "5041495244"); // "PAIRD"
    let pairedPool = makePoolData(ident(), "", PAIRED_TOKEN, 1_000_000_000n, 1_000_000_000n);
    market.query.addPool(pairedPool);
    market.preferredPools[PAIRED_TOKEN] = { pool: pairedPool.ident };
    // Each withdrawal pays out both of its pool's tokens together
    for (let [stable, paired] of [[1_000_000n, 2_000_000n], [3_000_000n, 4_000_000n]]) {
      let output = new Core.TransactionOutput(world.wallet, new Core.Value(2_000_000n, new Map([
        [Core.AssetId(STABLE_TOKEN), stable],
        [PAIRED_TOKEN, paired],
      ])));
      let input = new Core.TransactionInput(Core.TransactionId(crypto.randomBytes(32).toString("hex")), 0n);
      world.emulator.addUtxo(new Core.TransactionUnspentOutput(input, output));
    }

    await runConvert(world, market, { [STABLE_TOKEN]: "4000000", [PAIRED_TOKEN]: "6000000" });

    // One transaction carries both orders, and both are filled
    expect(world.provider.submissions.length).toBe(1);
    expect(market.scooper.filled.length).toBe(2);
    expect(walletBalance(world, STABLE_TOKEN)).toBe(0n);
    expect(walletBalance(world, PAIRED_TOKEN)).toBe(0n);
  });

  it("swaps a token without an ada pool in two rounds", async () => {
    fund(world, OTHER_TOKEN, 3_000_000n);
    let earned = await runConvert(world, market, { [OTHER_TOKEN]: "3000000" });

    // OTHER_TOKEN -> STABLE_TOKEN, then STABLE_TOKEN -> ada
    let intermediate = swapOutput(1_000_000_000n, 1_000_000_000n, 3_000_000n);
    let received = swapOutput(1_000_000_000n, 2_000_000_000n, intermediate);
    expect(market.scooper.filled.map((f) => f.received)).toEqual([
      [sdkAssetId(STABLE_TOKEN), intermediate],
      ["ada.lovelace", received],
    ]);
    expect(earned).toBe(received - 2n * market.scooper.protocolFee);
    expect(walletBalance(world, OTHER_TOKEN)).toBe(0n);
    expect(walletBalance(world, STABLE_TOKEN)).toBe(0n);
  });

  it("places orders for stableswap pools at the stableswap order script", async () => {
    market = makeMarket(world, EContractVersion.Stableswaps);
    fund(world, STABLE_TOKEN, 3_000_000n);
    await runConvert(world, market, { [STABLE_TOKEN]: "3000000" });

    expect(market.scooper.filled.length).toBe(1);
    expect(market.scooper.filled[0].order.output().address().getProps().paymentPart?.hash).toBe(STABLE_ORDER_HASH);
  });

  it("skips amounts too small to be worth swapping", async () => {
    fund(world, STABLE_TOKEN, 10n);
    let earned = await runConvert(world, market, { [STABLE_TOKEN]: "10" }, { minSwapReturn: 1_000n });

    expect(earned).toBe(0n);
    expect(world.provider.submissions.length).toBe(0);
  });

  it("waits for a scooper that takes a while", async () => {
    market.scooper.delayScoops = 3;
    fund(world, STABLE_TOKEN, 3_000_000n);
    let earned = await runConvert(world, market, { [STABLE_TOKEN]: "3000000" });

    expect(market.scooper.filled.length).toBe(1);
    expect(earned).toBe(swapOutput(1_000_000_000n, 2_000_000_000n, 3_000_000n) - market.scooper.protocolFee);
  });

  it("gives up when orders don't settle", async () => {
    market.scooper.delayScoops = 100;
    fund(world, STABLE_TOKEN, 3_000_000n);
    await expect(runConvert(world, market, { [STABLE_TOKEN]: "3000000" }, { maxPolls: 5 })).rejects.toThrow(/0\/1 settled after 5 checks/);
  });

  it("stops when the operator declines", async () => {
    fund(world, STABLE_TOKEN, 3_000_000n);
    await expect(runConvert(world, market, { [STABLE_TOKEN]: "3000000" }, { approve: async () => false })).rejects.toThrow(/Aborted/);
    expect(world.provider.submissions.length).toBe(0);
  });
});

describe("withdrawing stable pool fees and converting them to ada", () => {
  it("converts exactly the withdrawn tokens and totals the ada", async () => {
    let world = await makeWorld("stable");
    let market = makeMarket(world);

    let { withheld } = await runAutoWithdraw(world, 0n, { stable: true });
    // As written to the rewards-out file and read back by convertAssets
    let assets = JSON.parse(withheld.toJSON());

    let total = await runConvert(world, market, assets);

    // Each pool withholds a tenth of its fees
    let ada = 2n * ((STABLE_FEES[0] - 3_000_000n) / 10n + STABLE_FEES[1] / 10n);
    let tokens = 2n * (STABLE_FEES[2] / 10n);
    expect(assets).toEqual({ "": ada.toString(), [STABLE_TOKEN]: tokens.toString() });
    expect(market.scooper.filled.map((f) => f.offered)).toEqual([[sdkAssetId(STABLE_TOKEN), tokens]]);
    expect(total).toBe(ada + swapOutput(1_000_000_000n, 2_000_000_000n, tokens) - market.scooper.protocolFee);
    // The fixture settings use the wallet as the treasury, so only the
    // treasury's share of the withdrawn tokens is left. Those outputs carry the
    // treasury's Void datum, which keeps them out of the conversion.
    expect(walletBalance(world, STABLE_TOKEN)).toBe(2n * (STABLE_FEES[2] - STABLE_FEES[2] / 10n));
  });
});

describe("buyWithAda", () => {
  let world: World;
  let market: Market;

  beforeEach(async () => {
    world = await makeWorld("v3");
    market = makeMarket(world);
  });

  function runBuy(asset: string, amount: bigint, overrides: Partial<BuyWithAdaOptions> = {}) {
    return buyWithAda({
      blaze: world.blaze,
      provider: world.provider,
      queryProvider: market.query,
      walletAddress: world.wallet,
      preferredPools: market.preferredPools,
      asset,
      amount,
      approve: async () => true,
      confirmationTimeoutMs: 0,
      pollIntervalMs: 0,
      maxPolls: 10,
      sleep: async () => market.scooper.scoop(),
      ...overrides,
    });
  }

  it("buys the asset and reports what it received", async () => {
    let received = await runBuy(STABLE_TOKEN, 30_000_000n);

    let tokens = swapOutput(2_000_000_000n, 1_000_000_000n, 30_000_000n);
    expect(market.scooper.filled.map((f) => f.offered)).toEqual([["ada.lovelace", 30_000_000n]]);
    expect(walletBalance(world, STABLE_TOKEN)).toBe(tokens);
    // As written to the yield farming file and read by the payout step
    expect(JSON.parse(received.toJSON())).toEqual({
      "": (-market.scooper.protocolFee).toString(),
      [STABLE_TOKEN]: tokens.toString(),
    });
  });

  it("refuses a preferred pool that doesn't trade the asset for ada", async () => {
    await expect(runBuy(OTHER_TOKEN, 30_000_000n)).rejects.toThrow(/not ada for/);
    expect(world.provider.submissions.length).toBe(0);
  });

  it("gives up when the order doesn't settle", async () => {
    market.scooper.delayScoops = 100;
    await expect(runBuy(STABLE_TOKEN, 30_000_000n, { maxPolls: 5 })).rejects.toThrow(/0\/1 settled after 5 checks/);
  });

  it("stops when the operator declines", async () => {
    await expect(runBuy(STABLE_TOKEN, 30_000_000n, { approve: async () => false })).rejects.toThrow(/Aborted/);
    expect(world.provider.submissions.length).toBe(0);
  });
});
