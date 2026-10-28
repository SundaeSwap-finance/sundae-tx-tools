import { describe, it, expect, beforeEach } from "bun:test";
import * as crypto from "node:crypto";
import {
  CborSet,
  Ed25519PrivateNormalKeyHex,
  Hash28ByteBase16,
  HexBlob,
  NetworkId,
  Transaction,
  VkeyWitness,
  signMessage,
} from "@blaze-cardano/core";
import { Blaze, Core, HotSingleWallet } from "@blaze-cardano/sdk";
import { Emulator } from "@blaze-cardano/emulator";
import { computePayments, decodeAddressesFromJson, decodeReportFromJson, makeChange, makeRandomPool, makeScriptRef, makeSettings } from "./index.ts";
import { rebuildGenericStakeWithdrawal, runStage1, runStage2, type PipelineContext, type RunRecord } from "./pipeline.ts";
import { decodePoolDatum, decoder } from "./codec.ts";
import { fromHex } from "./util.ts";
import {
  ContentionProvider,
  FakeQueryProvider,
  FakeScooper,
  STABLE_FEES,
  STABLE_TOKEN,
  blueprint,
  makePoolData,
  makeStablePool,
  makeV3ScriptRef,
  scoopV3Pool,
  setTreasuryAllowance,
  stableBlueprint,
  stablePoolAddress,
  withMapExtensions,
} from "./testFixtures.ts";

// A whole month's run against an emulated ledger: v3 and stable pools holding
// fees, both stake addresses holding rewards, a market for the fake scooper to
// fill orders against, and a stake key standing in for the co-signer.

const SUNDAE = Core.AssetId("5d".repeat(28) + "53554e444145");
const GENERIC_REWARDS = 40_000_000n;
const POOL_STAKE_REWARDS = 60_000_000n;

function randomAddress(): Core.Address {
  return Core.Address.fromBytes(HexBlob("60" + crypto.randomBytes(28).toString("hex")));
}

// The scooper report: ALICE and the delegated SUNDAE scooped; BOB is an extra
// scooper who gets the flat reward without having scooped
const CSV = [
  "pub_key_hash,address,total_scoops,total_orders,total_protocol_fee,total_transaction_fee,total_num_mempool_orders",
  "aa,addr_alice,10,12,30000000,2000000,3",
  "bb,addr_sundae,20,25,20000000,3000000,4",
].join("\n");

interface Month {
  emulator: Emulator,
  provider: ContentionProvider,
  ctx: PipelineContext,
  scooper: FakeScooper,
  stakeKey: Core.Ed25519PrivateKey,
  record: () => RunRecord | undefined,
}

async function makeMonth(): Promise<Month> {
  await Core.initCrypto();
  let skey = Core.Ed25519PrivateKey.fromNormalBytes(crypto.randomBytes(32));
  let pkh = await (await skey.toPublic()).hash();
  let wallet = Core.Address.fromBytes(HexBlob("60" + pkh.hex()));

  let emulator = new Emulator([]);
  for (let i = 0; i < 10; i++) {
    emulator.addUtxo(makeChange(wallet, 100_000_000n));
  }
  emulator.addUtxo(withMapExtensions(makeSettings(blueprint, pkh)));
  // As on mainnet, the treasury admin may withhold everything
  setTreasuryAllowance(emulator, 1n, 1n);

  // Three v3 pools with 20 ADA of fees each, and two stable pools
  let v3PoolAddress;
  for (let i = 0; i < 3; i++) {
    let [pool] = makeRandomPool(blueprint, pkh);
    emulator.addUtxo(pool);
    v3PoolAddress = pool.output().address();
  }
  for (let i = 0; i < 2; i++) {
    emulator.addUtxo(makeStablePool(stablePoolAddress(pkh.hex()), STABLE_FEES)[0]);
  }
  let v3References = [
    makeScriptRef(wallet, HexBlob(blueprint.poolSpend.validator)),
    makeScriptRef(wallet, HexBlob(blueprint.poolManage.validator)),
  ];
  let stableReferences = [
    makeV3ScriptRef(wallet, stableBlueprint.poolSpend.validator),
    makeV3ScriptRef(wallet, stableBlueprint.poolManage.validator),
  ];
  [...v3References, ...stableReferences].forEach((r) => emulator.addUtxo(r));

  let scriptAccount = (hash: string) => Core.RewardAccount.fromCredential({ type: Core.CredentialType.ScriptHash, hash: Hash28ByteBase16(hash) }, NetworkId.Testnet);
  emulator.accounts.set(scriptAccount(blueprint.poolManage.hash), 0n);
  emulator.accounts.set(scriptAccount(stableBlueprint.poolManage.hash), 0n);
  let poolStakeAddress = scriptAccount(blueprint.poolStake.hash);
  emulator.accounts.set(poolStakeAddress, POOL_STAKE_REWARDS);
  let stakeKey = Core.Ed25519PrivateKey.fromNormalBytes(crypto.randomBytes(32));
  let genericStakeAddress = Core.RewardAccount.fromCredential({ type: Core.CredentialType.KeyHash, hash: Hash28ByteBase16((await stakeKey.toPublic()).hash().hex()) }, NetworkId.Testnet);
  emulator.accounts.set(genericStakeAddress, GENERIC_REWARDS);

  // 2 ADA per stable token, 1 ADA per SUNDAE
  let query = new FakeQueryProvider();
  let stablePool = makePoolData(crypto.randomBytes(28).toString("hex"), "", STABLE_TOKEN, 2_000_000_000n, 1_000_000_000n);
  let sundaePool = makePoolData(crypto.randomBytes(28).toString("hex"), "", SUNDAE, 1_000_000_000n, 1_000_000_000n);
  query.addPool(stablePool);
  query.addPool(sundaePool);
  let scooper = new FakeScooper(emulator, query);

  let provider = new ContentionProvider(emulator, blueprint.poolSpend.hash, scoopV3Pool);
  let blaze = await Blaze.from(provider, new HotSingleWallet(Ed25519PrivateNormalKeyHex(skey.hex()), NetworkId.Testnet, provider));

  let saved: RunRecord | undefined = undefined;
  let ctx: PipelineContext = {
    blaze,
    provider,
    queryProvider: query,
    walletAddress: wallet,
    signers: pkh.hex(),
    sundaeAssetId: SUNDAE,
    v3: { poolAddress: v3PoolAddress!.toBech32(), references: v3References.map((r) => r.input()), blueprint },
    stable: { poolAddress: stablePoolAddress(pkh.hex()).toBech32(), references: stableReferences.map((r) => r.input()), blueprint: stableBlueprint },
    genericStakeAddress,
    poolStakeAddress,
    preferredPools: { [STABLE_TOKEN]: { pool: stablePool.ident }, [SUNDAE]: { pool: sundaePool.ident } },
    scooperAddressesJson: JSON.stringify({
      scoopers: {
        ALICE: { new: "addr_alice", reward: randomAddress().toBech32() },
        BOB: { new: "addr_bob", reward: randomAddress().toBech32() },
        SUNDAE: { new: "addr_sundae", reward: randomAddress().toBech32() },
      },
    }),
    delegatedScoopers: { extraScoopers: ["BOB"], delegatedScoopers: ["SUNDAE"] },
    tokenHoldersDestination: randomAddress(),
    yieldFarmingDestination: randomAddress(),
    change: { count: 10n, amount: 10_000_000n },
    rewardBalance: async (stakeAddress) => emulator.accounts.get(stakeAddress) ?? 0n,
    retry: { approve: async () => true, maxAttempts: 3, retryDelayMs: 0, confirmationTimeoutMs: 0 },
    // Time passing between checks for settled orders is when the scooper acts
    orders: { confirmationTimeoutMs: 0, pollIntervalMs: 0, maxPolls: 10, sleep: async () => scooper.scoop() },
    store: {
      read: async () => saved && structuredClone(saved),
      write: async (record) => { saved = structuredClone(record); },
    },
    txLogDir: "",
  };
  return { emulator, provider, ctx, scooper, stakeKey, record: () => saved };
}

// The co-signer adds the stake key's witness, the wallet adds its own, and the
// co-signer submits
async function coSign(month: Month, tx: Transaction) {
  await month.ctx.blaze.signTransaction(tx);
  let witnesses = tx.witnessSet();
  let stakeWitness = new VkeyWitness((await month.stakeKey.toPublic()).hex(), signMessage(HexBlob(tx.getId()), month.stakeKey.hex()));
  witnesses.setVkeys(CborSet.fromCore([...witnesses.vkeys()!.toCore(), stakeWitness.toCore()], VkeyWitness.fromCore));
  tx.setWitnessSet(witnesses);
  await month.provider.postTransactionToChain(tx);
}

// The wallet's ada, including the payouts of its swap orders (which carry the
// order's identifier as a bytestring datum) but not the treasury's outputs
// (the fixture treasury is the wallet, paid with a Void datum)
function walletAda(month: Month): bigint {
  return month.emulator.utxos()
    .filter((u) => u.output().address().toBytes() == month.ctx.walletAddress.toBytes() && !u.output().scriptRef())
    .filter((u) => !u.output().datum() || u.output().datum()!.asInlineData()?.asBoundedBytes())
    .reduce((n, u) => n + u.output().amount().coin(), 0n);
}

function v3Fees(month: Month): bigint {
  return month.emulator.utxos()
    .filter((u) => u.output().address().toBech32() == month.ctx.v3.poolAddress)
    .reduce((n, u) => n + decodePoolDatum(decoder(fromHex(u.output().datum()!.asInlineData()!.toCbor()))).protocolFees, 0n);
}

async function runMonth(month: Month): Promise<string> {
  await coSign(month, await runStage1(month.ctx, "2026-10"));
  return await runStage2(month.ctx, () => CSV);
}

describe("the monthly revenue run", () => {
  let month: Month;

  beforeEach(async () => {
    month = await makeMonth();
  });

  it("pays out the month from the fees and rewards it withdraws", async () => {
    let adaBefore = walletAda(month);
    let feesBefore = v3Fees(month);

    let genericTx = await runStage1(month.ctx, "2026-10");
    // Nothing goes ahead until the co-signer has submitted
    await expect(runStage2(month.ctx, () => CSV)).rejects.toThrow(/isn't confirmed/);
    await coSign(month, genericTx);
    let payoutId = await runStage2(month.ctx, () => CSV);

    let record = month.record()!;
    let report = JSON.parse(record.report!);
    // The report counts what was withdrawn, less the pool stake's 2 ADA to the
    // treasury
    expect(report.rewards).toEqual({
      [month.ctx.genericStakeAddress]: Number(GENERIC_REWARDS),
      [month.ctx.poolStakeAddress]: Number(POOL_STAKE_REWARDS - 2_000_000n),
    });
    expect(month.emulator.accounts.get(month.ctx.genericStakeAddress)).toBe(0n);
    expect(month.emulator.accounts.get(month.ctx.poolStakeAddress)).toBe(0n);
    expect(report.extraStableswapRevenue).toBe(Number(record.conversion!.ada));
    expect(report.extraStableswapRevenue).toBeGreaterThan(0);
    // Exactly the protocol fees the report asked for came out of the v3 pools
    expect(feesBefore - v3Fees(month)).toBe(BigInt(report.payments.protocolFeesNeeded));
    expect(report.payments.protocolFeesNeeded).toBeGreaterThan(0);

    // The payout pays what the report says, and the yield farming SUNDAE bought
    let payoutTx = month.provider.submissions.find((tx) => tx.getId() == payoutId)!;
    let paid = new Map(payoutTx.body().outputs().map((o) => [o.address().toBech32(), o.amount()]));
    let decoded = decodeReportFromJson(record.report!);
    for (let payment of computePayments(decoded, decodeAddressesFromJson(month.ctx.scooperAddressesJson))) {
      expect(paid.get(payment.address.toBech32())!.coin()).toBe(payment.lovelace);
    }
    expect(paid.get(month.ctx.tokenHoldersDestination.toBech32())!.coin()).toBe(decoded.payments.tokenHoldersFee);
    let farm = paid.get(month.ctx.yieldFarmingDestination.toBech32())!;
    expect(farm.multiasset()?.get(SUNDAE)).toBe(BigInt(record.sundaePurchase!.sundae));
    expect(BigInt(record.sundaePurchase!.sundae)).toBeGreaterThan(0n);

    // The month's withdrawals paid for it: the wallet is out only fees and the
    // treasury's minimum shares
    let spent = adaBefore - walletAda(month);
    expect(spent).toBeGreaterThan(0n);
    expect(spent).toBeLessThan(15_000_000n);
  });

  it("does nothing when a finished stage is run again", async () => {
    await runMonth(month);
    let submitted = month.provider.submissions.length;

    await runStage1(month.ctx, "2026-10");
    await runStage2(month.ctx, () => CSV);
    expect(month.provider.submissions.length).toBe(submitted);
  });

  it("picks up where a failed stage left off", async () => {
    // Decline the payout, which is the only transaction with metadata
    let declinePayout = true;
    month.ctx.retry.approve = async (tx) => !(declinePayout && tx.auxiliaryData());
    await coSign(month, await runStage1(month.ctx, "2026-10"));
    await expect(runStage2(month.ctx, () => CSV)).rejects.toThrow(/Aborted/);
    let feesAfterFirstTry = v3Fees(month);
    let submitted = month.provider.submissions.length;

    declinePayout = false;
    await runStage2(month.ctx, () => CSV);
    // Only the payout ran: no second withdrawal or purchase
    expect(v3Fees(month)).toBe(feesAfterFirstTry);
    expect(month.provider.submissions.length).toBe(submitted + 1);
    expect(month.record()!.payout).toBeDefined();
  });

  it("rebuilds a generic stake withdrawal that can no longer land", async () => {
    let stale = await runStage1(month.ctx, "2026-10");
    // An epoch passes before the co-signer submits, and the balance grows
    month.emulator.accounts.set(month.ctx.genericStakeAddress, GENERIC_REWARDS + 5_000_000n);
    await expect(coSign(month, stale)).rejects.toThrow(/does not match the actual reward balance/);
    await expect(runStage2(month.ctx, () => CSV)).rejects.toThrow(/isn't confirmed/);

    await coSign(month, await rebuildGenericStakeWithdrawal(month.ctx));
    await runStage2(month.ctx, () => CSV);
    let report = JSON.parse(month.record()!.report!);
    expect(report.rewards[month.ctx.genericStakeAddress]).toBe(Number(GENERIC_REWARDS + 5_000_000n));
  });

  it("won't rebuild a generic stake withdrawal that landed", async () => {
    await coSign(month, await runStage1(month.ctx, "2026-10"));
    await expect(rebuildGenericStakeWithdrawal(month.ctx)).rejects.toThrow(/landed/);
  });

  it("won't start stage 2 before stage 1 is finished", async () => {
    await expect(runStage2(month.ctx, () => CSV)).rejects.toThrow(/Stage 1 isn't finished/);

    // Stage 1 stops at the conversion, when the scooper doesn't fill its order
    month.scooper.delayScoops = 100;
    await expect(runStage1(month.ctx, "2026-10")).rejects.toThrow(/settled/);
    await expect(runStage2(month.ctx, () => CSV)).rejects.toThrow(/missing conversion, poolStakeWithdrawal, genericStakeWithdrawal/);
  });

  it("won't continue another month's run", async () => {
    await runStage1(month.ctx, "2026-10");
    await expect(runStage1(month.ctx, "2026-11")).rejects.toThrow(/for 2026-10, not 2026-11/);
  });
});

// Approves every transaction except the one at the given position, and keeps
// track of what it approved
function auditedApprover(declineAt = Infinity) {
  let audit = {
    calls: 0,
    approved: new Set<string>(),
    declined: undefined as string | undefined,
    approve: async (tx: Transaction) => {
      if (audit.calls++ == declineAt) {
        audit.declined = tx.getId();
        return false;
      }
      audit.approved.add(tx.getId());
      return true;
    },
  };
  return audit;
}

// Submissions other than the co-signer's
function pipelineSubmissions(month: Month): string[] {
  let generic = month.record()?.genericStakeWithdrawal?.txId;
  return month.provider.submissions.map((tx) => tx.getId()).filter((id) => id != generic);
}

describe("approval", () => {
  it("is given for every transaction the run submits", async () => {
    let month = await makeMonth();
    let audit = auditedApprover();
    month.ctx.retry.approve = audit.approve;
    await runMonth(month);

    let submitted = pipelineSubmissions(month);
    expect(submitted.length).toBeGreaterThan(0);
    expect(submitted.filter((id) => !audit.approved.has(id))).toEqual([]);
  });

  it("when withheld, stops the run before that transaction or any later one is submitted", async () => {
    // How many transactions a whole run asks to approve
    let full = await makeMonth();
    let fullAudit = auditedApprover();
    full.ctx.retry.approve = fullAudit.approve;
    await runMonth(full);
    // Each step asks at least once
    expect(fullAudit.calls).toBeGreaterThanOrEqual(7);

    for (let declineAt = 0; declineAt < fullAudit.calls; declineAt++) {
      let month = await makeMonth();
      let audit = auditedApprover(declineAt);
      month.ctx.retry.approve = audit.approve;
      await expect(runMonth(month)).rejects.toThrow(/Aborted/);

      // Only what was approved before the declined transaction went out
      expect(audit.declined).toBeDefined();
      expect(pipelineSubmissions(month)).toEqual([...audit.approved]);
      expect(audit.calls).toBe(declineAt + 1);
    }
  // A whole run per approval
  }, 120_000);
});
