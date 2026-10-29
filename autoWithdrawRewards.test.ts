import { describe, it, expect, beforeEach } from "bun:test";
import { Transaction, TransactionUnspentOutput } from "@blaze-cardano/core";
import { makeChangeUtxos, stableWithdrawalTokens, submitAndAwaitWithRetry } from "./index.ts";
import { decodePoolDatum, decodeStablePoolDatum, decoder } from "./codec.ts";
import { fromHex } from "./util.ts";
import {
  SCOOP_FEE,
  STABLE_FEES,
  STABLE_TOKEN,
  inflatePoolFees,
  makeWorld,
  runAutoWithdraw,
  type World,
} from "./testFixtures.ts";

// These tests run the real auto-withdrawal against an emulated ledger with the
// real pool scripts, and script the kinds of contention we see on mainnet:
// scooper spending a pool right before our submission lands, the chain indexer
// lagging behind, and transactions that get dropped or confirmed late.

// Each fixture pool has 17 ADA withdrawable (20 ADA of fees less 3 ADA left
// behind), so this takes all of two pools and part of the third. The partial
// withdrawal still withholds more than min-ADA; below that, the builder tops
// up the withheld output from change.
const NEEDED = 44_000_000n;

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

function firstPool(world: World): TransactionUnspentOutput {
  return world.emulator.utxos().find((u) => u.output().address().toBytes() == world.poolAddress.toBytes())!;
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
    let { rewards, withheld } = await runAutoWithdraw(world, NEEDED);

    let withdrawn = withdrawnPerPool(world);
    expect([...withdrawn.values()].sort()).toEqual([17_000_000n, 17_000_000n, 10_000_000n].sort());
    expect(world.provider.submissions.length).toBe(3);
    expect(coins(rewards)).toBe(sum([...withdrawn.values()].map(withheldShare)));
    expect(withheld.get("")).toBe(sum([...withdrawn.values()].map(withheldShare)));
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

  it("skips a pool whose datum claims more fees than it holds", async () => {
    let broken = inflatePoolFees(world.emulator, firstPool(world), false);
    let brokenFees = currentFees(world).get(broken);
    await runAutoWithdraw(world, 30_000_000n);

    // The other two pools give 17 + 13 ADA
    expect(currentFees(world).get(broken)).toBe(brokenFees);
    expect(world.provider.submissions.length).toBe(2);
    let withdrawn = withdrawnPerPool(world);
    withdrawn.delete(broken);
    expect(sum(withdrawn.values())).toBe(30_000_000n);
  });

  it("reports no rewards when the whole withdrawal goes to the treasury", async () => {
    // The treasury takes at least 1 ADA, so nothing is withheld
    let { rewards, change, withheld } = await runAutoWithdraw(world, 1_000_000n);
    expect(withheld.get("")).toBe(0n);

    expect(sum(withdrawnPerPool(world).values())).toBe(1_000_000n);
    expect(rewards).toEqual([]);
    expect(change.length).toBe(1);
  });
});

// Pool ident -> [flat, asset A, asset B] protocol fees currently on the ledger
function currentStableFees(world: World): Map<string, [bigint, bigint, bigint]> {
  let fees = new Map();
  for (let utxo of world.emulator.utxos()) {
    if (utxo.output().address().toBytes() != world.poolAddress.toBytes()) {
      continue;
    }
    let datum = decodeStablePoolDatum(decoder(fromHex(utxo.output().datum()!.asInlineData()!.toCbor())));
    fees.set(datum.identifier.toString("hex"), datum.protocolFees);
  }
  return fees;
}

describe("autoWithdrawRewards on stable pools", () => {
  let world: World;

  beforeEach(async () => {
    world = await makeWorld("stable");
  });

  // Everything but 3 ADA of flat fees is withdrawn. The fixture settings allow
  // us to withhold 1/10 of each part, rounded down as the pool.manage script
  // does, and the treasury gets the rest.
  function withheld(fees: [bigint, bigint, bigint]): { ada: bigint, tokens: bigint } {
    return {
      ada: (fees[0] - 3_000_000n) / 10n + fees[1] / 10n,
      tokens: fees[2] / 10n,
    };
  }

  function expectRewards(rewards: TransactionUnspentOutput[], fees = STABLE_FEES) {
    expect(rewards.length).toBe(2);
    for (let reward of rewards) {
      expect(reward.output().amount().multiasset()?.get(STABLE_TOKEN)).toBe(withheld(fees).tokens);
      // The builder tops this output up to min-ADA from change, so it can hold
      // more ADA than was withheld
      expect(reward.output().amount().coin()).toBeGreaterThanOrEqual(withheld(fees).ada);
    }
  }

  it("pays the treasury its rounded-up share when fees don't divide evenly", async () => {
    let fees: [bigint, bigint, bigint] = [10_000_007n, 1_000_003n, 5_000_009n];
    world = await makeWorld("stable", fees);
    let { rewards } = await runAutoWithdraw(world, 0n, { stable: true });

    expect(world.provider.submissions.length).toBe(2);
    for (let tx of world.provider.submissions) {
      let treasury = tx.body().outputs()[1].amount();
      expect(treasury.coin()).toBe(fees[0] - 3_000_000n + fees[1] - withheld(fees).ada);
      expect(treasury.multiasset()?.get(STABLE_TOKEN)).toBe(fees[2] - withheld(fees).tokens);
    }
    expectRewards(rewards, fees);
  });

  it("reports exactly what was withheld, not the min-ADA top-up", async () => {
    let { rewards, withheld: reported } = await runAutoWithdraw(world, 0n, { stable: true });

    // Each reward output was topped up past what was withheld
    let expected = withheld(STABLE_FEES);
    expect(coins(rewards)).toBeGreaterThan(2n * expected.ada);
    expect(reported.get("")).toBe(2n * expected.ada);
    expect(reported.get(STABLE_TOKEN)).toBe(2n * expected.tokens);
  });

  it("withdraws all fees but the flat 3 ADA from every pool", async () => {
    let { rewards } = await runAutoWithdraw(world, 0n, { stable: true });

    expect(world.provider.submissions.length).toBe(2);
    for (let fees of currentStableFees(world).values()) {
      expect(fees).toEqual([3_000_000n, 0n, 0n]);
    }
    expectRewards(rewards);
  });

  it("skips a pool whose datum claims more fees than it holds", async () => {
    let broken = inflatePoolFees(world.emulator, firstPool(world), true);
    let brokenFees = currentStableFees(world).get(broken);
    await runAutoWithdraw(world, 0n, { stable: true });

    expect(world.provider.submissions.length).toBe(1);
    expect(currentStableFees(world).get(broken)).toEqual(brokenFees);
  });

  it("leaves the pools the config skips alone", async () => {
    let idents = [...currentStableFees(world).keys()];
    let skippedFees = currentStableFees(world).get(idents[0]);
    expect(await stableWithdrawalTokens(world.provider, world.poolAddress.toBech32(), [idents[0]])).toEqual([STABLE_TOKEN]);
    expect(await stableWithdrawalTokens(world.provider, world.poolAddress.toBech32(), idents)).toEqual([]);

    await runAutoWithdraw(world, 0n, { stable: true, skipPools: [idents[0]] });
    expect(world.provider.submissions.length).toBe(1);
    expect(currentStableFees(world).get(idents[0])).toEqual(skippedFees);
    expect(currentStableFees(world).get(idents[1])).toEqual([3_000_000n, 0n, 0n]);
  });

  it("retries a withdrawal whose pool was scooped first", async () => {
    world.provider.script = ["scoopFirst"];
    world.provider.staleReadsAfterScoop = 1;
    let { rewards } = await runAutoWithdraw(world, 0n, { stable: true });

    // One rejection after the scoop, one against the stale pool, then success
    expect(world.provider.submissions.length).toBe(4);
    // The amounts were fixed before the scoop, so the scoop's fees stay behind
    let remaining = [...currentStableFees(world).values()].map((f) => f[0]).sort();
    expect(remaining).toEqual([3_000_000n, 3_000_000n + SCOOP_FEE].sort());
    for (let fees of currentStableFees(world).values()) {
      expect(fees.slice(1)).toEqual([0n, 0n]);
    }
    expectRewards(rewards);
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

// The run's funds in one wallet and the treasury admin's key in another, as
// on preview, where the admin's address holds a reference script the run
// mustn't spend
describe("with a separate treasury admin", () => {
  function vkeyCount(tx: Transaction): number {
    return tx.witnessSet().vkeys()?.size() ?? 0;
  }

  it("signs the v3 withdrawals as both the wallet and the admin", async () => {
    let world = await makeWorld("v3", STABLE_FEES, { separateAdmin: true });
    await runAutoWithdraw(world, NEEDED);

    expect(world.provider.submissions.length).toBe(3);
    expect(world.provider.submissions.map(vkeyCount)).toEqual([2, 2, 2]);
  });

  it("signs the stable withdrawals as both the wallet and the admin", async () => {
    let world = await makeWorld("stable", STABLE_FEES, { separateAdmin: true });
    await runAutoWithdraw(world, 0n, { stable: true });

    expect(world.provider.submissions.length).toBe(2);
    expect(world.provider.submissions.map(vkeyCount)).toEqual([2, 2]);
  });

  it("leaves the admin's signature off transactions that don't need it", async () => {
    let world = await makeWorld("v3", STABLE_FEES, { separateAdmin: true });
    await makeChangeUtxos({
      blaze: world.blaze,
      provider: world.provider,
      walletAddress: world.wallet,
      count: 2n,
      amount: 10_000_000n,
      retry: { approve: async () => true, maxAttempts: 1, retryDelayMs: 0, confirmationTimeoutMs: 0 },
      txLogDir: "",
    });
    expect(world.provider.submissions.map(vkeyCount)).toEqual([1]);
  });
});
