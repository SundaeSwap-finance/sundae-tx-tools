// The monthly revenue run, as two stages around the one step we can't
// automate, the co-signed generic stake withdrawal:
//
//   stage 1: make change, withdraw the stable pool fees, convert them to ada,
//            withdraw the pool stake rewards, and build the generic stake
//            withdrawal for the co-signer
//   (the co-signer signs and submits the generic stake withdrawal)
//   stage 2: confirm the generic stake withdrawal, build the report from the
//            amounts withdrawn, withdraw the v3 protocol fees it needs, buy
//            SUNDAE for yield farming, and pay out
//
// Each step's result goes into the month's run record as soon as the step is
// done, and a step that's already in the record isn't run again. So a stage
// that fails can be rerun to pick up where it left off, and rerunning a
// finished stage does nothing. A step that fails partway through itself (say,
// after the first of several withdrawals) needs looking at by hand.
import * as fs from "node:fs";
import minimist from "minimist";
import { Core } from "@blaze-cardano/sdk";
import type { Blaze, Provider, Wallet } from "@blaze-cardano/sdk";
import { QueryProviderSundaeSwap } from "@sundaeswap/core";
import {
  autoWithdrawRewards,
  blockfrostRewardBalance,
  buyWithAda,
  checkPayoutTotals,
  cliApprover,
  collectChangeMa,
  computePayments,
  convertAssetsToAda,
  decodeAddressesFromJson,
  decodeBlueprint,
  decodeReportFromJson,
  defaultConvertAssetsTiming,
  defaultRetryOptions,
  displayPreviousMonth,
  makeChangeUtxos,
  payout,
  payoutChangeNeeded,
  readReferences,
  setupBlaze,
  withdrawGenericStake,
  withdrawPoolStakeRewards,
  type Blueprint,
  type RetryOptions,
  type RewardBalance,
  type SwapQueryProvider,
} from "./index.ts";
import { buildReport, parseScooperCsv, reportToJson } from "./report.ts";
import { applyConfig, readConfig, type NetworkConfig } from "./config.ts";

// Amounts are strings, so the record is plain JSON
export interface RunRecord {
  // The month being paid out, as YYYY-MM
  month: string,
  // Stage 1
  makeChange?: { txId: string },
  stableWithdrawal?: { withheld: Record<string, string> },
  conversion?: { ada: string },
  poolStakeWithdrawal?: { txId: string, withdrawn: string, withheld: string },
  genericStakeWithdrawal?: { txId: string, tx: string, withdrawn: string },
  // Stage 2
  genericStakeConfirmed?: { txId: string },
  report?: string,
  v3Withdrawal?: { withheld: Record<string, string> },
  sundaePurchase?: { sundae: string },
  payout?: { txId: string },
}

const STAGE_1_STEPS = ["makeChange", "stableWithdrawal", "conversion", "poolStakeWithdrawal", "genericStakeWithdrawal"] as const;

// Where a month's run record lives: a file locally, S3 in a Lambda
export interface RunStore {
  read(): Promise<RunRecord | undefined>,
  write(record: RunRecord): Promise<void>,
}

export function fileRunStore(path: string): RunStore {
  return {
    read: async () => fs.existsSync(path) ? JSON.parse(fs.readFileSync(path, "utf8")) : undefined,
    write: async (record) => fs.writeFileSync(path, JSON.stringify(record, null, 2) + "\n"),
  };
}

interface ProtocolContext {
  poolAddress: string,
  references: Core.TransactionInput[],
  blueprint: Blueprint,
}

export interface PipelineContext {
  blaze: Blaze<Provider, Wallet>,
  provider: Provider,
  queryProvider: SwapQueryProvider,
  // Withdrawals pay what they withhold here too, since the later steps spend it
  walletAddress: Core.Address,
  signers: string,
  sundaeAssetId: string,
  v3: ProtocolContext,
  stable: ProtocolContext,
  genericStakeAddress: Core.RewardAccount,
  poolStakeAddress: Core.RewardAccount,
  preferredPools: Record<string, { pool: string }>,
  // As in scooper-addresses.json and delegated-scoopers.json
  scooperAddressesJson: string,
  delegatedScoopers: { extraScoopers: string[], delegatedScoopers: string[] },
  tokenHoldersDestination: Core.Address,
  yieldFarmingDestination: Core.Address,
  // The change utxos stage 1 starts by making
  change: { count: bigint, amount: bigint },
  rewardBalance: RewardBalance,
  retry: RetryOptions,
  orders: { confirmationTimeoutMs: number, pollIntervalMs: number, maxPolls: number, sleep: (ms: number) => Promise<void> },
  store: RunStore,
  txLogDir: string,
}

// Runs a step unless the record already has its result, and saves the result
// as soon as it's done
async function step<K extends keyof RunRecord>(ctx: PipelineContext, record: RunRecord, name: K, run: () => Promise<NonNullable<RunRecord[K]>>): Promise<NonNullable<RunRecord[K]>> {
  let done = record[name];
  if (done !== undefined) {
    console.log(`${name}: already done`);
    return done!;
  }
  console.log(`${name}...`);
  let result = await run();
  record[name] = result;
  await ctx.store.write(record);
  return result;
}

function json(value: { toJSON(): string }): Record<string, string> {
  return JSON.parse(value.toJSON());
}

// Stage 1. Returns the generic stake withdrawal for the co-signer to sign and
// submit.
export async function runStage1(ctx: PipelineContext, month: string): Promise<Core.Transaction> {
  let record = await ctx.store.read() ?? { month };
  if (record.month != month) {
    throw new Error(`The run record is for ${record.month}, not ${month}`);
  }
  let withdrawalOptions = {
    blaze: ctx.blaze,
    provider: ctx.provider,
    walletAddress: ctx.walletAddress,
    withheldAddress: ctx.walletAddress,
    signers: ctx.signers,
    retry: ctx.retry,
    txLogDir: ctx.txLogDir,
    todo: undefined,
  };
  let orderOptions = {
    blaze: ctx.blaze,
    provider: ctx.provider,
    queryProvider: ctx.queryProvider,
    walletAddress: ctx.walletAddress,
    preferredPools: ctx.preferredPools,
    approve: ctx.retry.approve,
    ...ctx.orders,
  };

  await step(ctx, record, "makeChange", async () => {
    let made = await makeChangeUtxos({
      blaze: ctx.blaze,
      provider: ctx.provider,
      walletAddress: ctx.walletAddress,
      count: ctx.change.count,
      amount: ctx.change.amount,
      retry: ctx.retry,
      txLogDir: ctx.txLogDir,
    });
    return { txId: made[0].input().transactionId() };
  });

  let stable = await step(ctx, record, "stableWithdrawal", async () => {
    let { withheld } = await autoWithdrawRewards({
      ...withdrawalOptions,
      poolAddress: ctx.stable.poolAddress,
      needed: 0n,
      blueprint: ctx.v3.blueprint,
      stableBlueprint: ctx.stable.blueprint,
      references: ctx.stable.references,
      stable: true,
    });
    return { withheld: json(withheld) };
  });

  await step(ctx, record, "conversion", async () => {
    let ada = await convertAssetsToAda({ ...orderOptions, assets: stable.withheld, minSwapReturn: 1n });
    return { ada: ada.toString() };
  });

  await step(ctx, record, "poolStakeWithdrawal", async () => {
    let { tx, withdrawn, withheld } = await withdrawPoolStakeRewards({
      ...withdrawalOptions,
      stakeAddress: ctx.poolStakeAddress,
      rewardBalance: ctx.rewardBalance,
      blueprint: ctx.v3.blueprint,
    });
    return { txId: tx.getId(), withdrawn: withdrawn.toString(), withheld: withheld.toString() };
  });

  let generic = await step(ctx, record, "genericStakeWithdrawal", () => buildGenericStakeWithdrawal(ctx));
  return Core.Transaction.fromCbor(Core.TxCBOR(generic.tx));
}

async function buildGenericStakeWithdrawal(ctx: PipelineContext): Promise<NonNullable<RunRecord["genericStakeWithdrawal"]>> {
  let { tx, withdrawn } = await withdrawGenericStake({
    blaze: ctx.blaze,
    provider: ctx.provider,
    walletAddress: ctx.walletAddress,
    stakeAddress: ctx.genericStakeAddress,
    rewardBalance: ctx.rewardBalance,
    // Built for the co-signer, who has the stake key
    stakeKey: undefined,
    retry: undefined,
    txLogDir: ctx.txLogDir,
  });
  return { txId: tx.getId(), tx: tx.toCbor(), withdrawn: withdrawn.toString() };
}

// Replaces a generic stake withdrawal that can no longer land, e.g. because an
// epoch passed before the co-signer submitted it, so the balance changed
export async function rebuildGenericStakeWithdrawal(ctx: PipelineContext): Promise<Core.Transaction> {
  let record = await ctx.store.read();
  if (!record?.genericStakeWithdrawal) {
    throw new Error("Stage 1 hasn't built the generic stake withdrawal yet");
  }
  if (record.genericStakeConfirmed) {
    throw new Error(`The generic stake withdrawal ${record.genericStakeConfirmed.txId} is already confirmed`);
  }
  if (await ctx.provider.awaitTransactionConfirmation(Core.TransactionId(record.genericStakeWithdrawal.txId), 0)) {
    throw new Error(`The generic stake withdrawal ${record.genericStakeWithdrawal.txId} landed; run stage 2`);
  }
  record.genericStakeWithdrawal = await buildGenericStakeWithdrawal(ctx);
  await ctx.store.write(record);
  return Core.Transaction.fromCbor(Core.TxCBOR(record.genericStakeWithdrawal.tx));
}

// Stage 2, once the co-signer has submitted the generic stake withdrawal. The
// scooper report CSV is only read if the report hasn't been built yet. Returns
// the payout's transaction id.
export async function runStage2(ctx: PipelineContext, scooperCsv: (() => string) | undefined): Promise<string> {
  let record = await ctx.store.read();
  let missing = STAGE_1_STEPS.filter((name) => !record?.[name]);
  if (!record || missing.length > 0) {
    throw new Error(`Stage 1 isn't finished (missing ${missing.join(", ")})`);
  }
  let generic = record.genericStakeWithdrawal!;

  await step(ctx, record, "genericStakeConfirmed", async () => {
    if (!(await ctx.provider.awaitTransactionConfirmation(Core.TransactionId(generic.txId), ctx.retry.confirmationTimeoutMs))) {
      throw new Error(`The generic stake withdrawal ${generic.txId} isn't confirmed. If the co-signer has yet to submit it, run stage 2 again once they have; if it can no longer land (e.g. an epoch passed), rebuild it.`);
    }
    return { txId: generic.txId };
  });

  let reportJson = await step(ctx, record, "report", async () => {
    if (!scooperCsv) {
      throw new Error("The report needs the scooper report CSV");
    }
    let report = buildReport({
      rows: parseScooperCsv(scooperCsv()),
      scooperAddresses: JSON.parse(ctx.scooperAddressesJson).scoopers,
      extraScoopers: ctx.delegatedScoopers.extraScoopers,
      delegatedScoopers: ctx.delegatedScoopers.delegatedScoopers,
      // What reached the wallet
      stakingRewards: {
        [ctx.genericStakeAddress]: BigInt(generic.withdrawn),
        [ctx.poolStakeAddress]: BigInt(record.poolStakeWithdrawal!.withheld),
      },
      extraStableswapRevenue: BigInt(record.conversion!.ada),
    });
    return reportToJson(report);
  });
  let report = decodeReportFromJson(reportJson);
  let addresses = decodeAddressesFromJson(ctx.scooperAddressesJson);
  let payments = computePayments(report, addresses);
  checkPayoutTotals(report, payments);

  await step(ctx, record, "v3Withdrawal", async () => {
    if (report.payments.protocolFeesNeeded == 0n) {
      return { withheld: {} };
    }
    let { withheld } = await autoWithdrawRewards({
      blaze: ctx.blaze,
      provider: ctx.provider,
      walletAddress: ctx.walletAddress,
      withheldAddress: ctx.walletAddress,
      signers: ctx.signers,
      retry: ctx.retry,
      txLogDir: ctx.txLogDir,
      todo: undefined,
      poolAddress: ctx.v3.poolAddress,
      needed: report.payments.protocolFeesNeeded,
      blueprint: ctx.v3.blueprint,
      stableBlueprint: undefined,
      references: ctx.v3.references,
      stable: false,
    });
    return { withheld: json(withheld) };
  });

  let purchase = await step(ctx, record, "sundaePurchase", async () => {
    let received = await buyWithAda({
      blaze: ctx.blaze,
      provider: ctx.provider,
      queryProvider: ctx.queryProvider,
      walletAddress: ctx.walletAddress,
      preferredPools: ctx.preferredPools,
      approve: ctx.retry.approve,
      ...ctx.orders,
      asset: ctx.sundaeAssetId,
      amount: report.payments.yieldFarming,
    });
    return { sundae: received.get(ctx.sundaeAssetId).toString() };
  });

  // Recorded as soon as it's submitted, so a rerun waits for this payout
  // rather than making another
  let paid = await step(ctx, record, "payout", async () => {
    let yieldFarmingAmount = BigInt(purchase.sundae);
    let tx = await payout({
      blaze: ctx.blaze,
      // The SUNDAE is in the payout of the purchase order, which has settled
      changeUtxos: await collectChangeMa(ctx.provider, ctx.walletAddress, payoutChangeNeeded(report, ctx.sundaeAssetId, yieldFarmingAmount), true),
      report,
      tokenHoldersDestination: ctx.tokenHoldersDestination,
      yieldFarmingDestination: ctx.yieldFarmingDestination,
      yieldFarmingAmount,
      scooperPayments: payments,
      approve: ctx.retry.approve,
      addresses,
      txLogDir: ctx.txLogDir,
      sundaeAssetId: ctx.sundaeAssetId,
      month: record.month,
    });
    return { txId: tx.getId() };
  });
  if (!(await ctx.provider.awaitTransactionConfirmation(Core.TransactionId(paid.txId), ctx.retry.confirmationTimeoutMs))) {
    throw new Error(`The payout ${paid.txId} was submitted but isn't confirmed yet; check it on chain before doing anything else`);
  }
  console.log(`Paid out ${record.month} in ${paid.txId}`);
  return paid.txId;
}

// The pipeline context for a config, on the real network
export async function cliContext(argv: any, config: NetworkConfig, store: RunStore): Promise<PipelineContext> {
  let { blaze, provider } = await setupBlaze(argv);
  let address = (a: string) => Core.addressFromBech32(a);
  let readJson = (path: string) => JSON.parse(fs.readFileSync(path, "utf8"));
  let required = <T>(value: T | undefined, name: string): T => {
    if (value === undefined) {
      throw new Error(`The pipeline needs ${name} in the config`);
    }
    return value;
  };
  // Config values, as applyConfig gave them to the command line flags
  let configured = (flag: string) => required(argv[flag], flag);
  let protocol = (p: typeof config.v3, name: string): ProtocolContext => {
    if (!p?.poolAddress || !p.references || !p.blueprint) {
      throw new Error(`The pipeline needs ${name}.poolAddress, ${name}.references and ${name}.blueprint in the config`);
    }
    return { poolAddress: p.poolAddress, references: readReferences(p.references), blueprint: decodeBlueprint(fs.readFileSync(p.blueprint, "utf8")) };
  };
  let approve = await cliApprover(!!argv.forceSubmit);
  return {
    blaze,
    provider,
    queryProvider: new QueryProviderSundaeSwap(argv.mainnet ? "mainnet" : "preview"),
    walletAddress: address(configured("walletAddress")),
    signers: configured("signers"),
    sundaeAssetId: configured("sundaeAssetId"),
    v3: protocol(config.v3, "v3"),
    stable: protocol(config.stable, "stable"),
    genericStakeAddress: required(config.genericStakeAddress, "genericStakeAddress") as Core.RewardAccount,
    poolStakeAddress: required(config.poolStakeAddress, "poolStakeAddress") as Core.RewardAccount,
    preferredPools: readJson(configured("preferredPoolsFile")),
    scooperAddressesJson: fs.readFileSync(configured("scooperAddresses"), "utf8"),
    delegatedScoopers: readJson(configured("delegatedScoopersFile")),
    tokenHoldersDestination: address(configured("tokenHoldersDestination")),
    yieldFarmingDestination: address(configured("yieldFarmingDestination")),
    change: { count: BigInt(argv.changeCount ?? 20), amount: BigInt(argv.changeAmount ?? 10_000_000) },
    rewardBalance: blockfrostRewardBalance(!!argv.mainnet),
    retry: { ...defaultRetryOptions, approve },
    orders: defaultConvertAssetsTiming,
    store,
    txLogDir: argv.txLogDir,
  };
}

// bun run pipeline.ts --config mainnet.config.json --stage 1 [--month YYYY-MM]
// bun run pipeline.ts --config mainnet.config.json --stage 2 --scooperCsv report.csv [--month YYYY-MM]
// bun run pipeline.ts --config mainnet.config.json --rebuildGenericStake [--month YYYY-MM]
// The month defaults to last month, and its record to run-YYYY-MM.json.
if (import.meta.main) {
  let argv = minimist(process.argv.slice(2));
  if (!argv.config) {
    throw new Error("Expected --config");
  }
  let config = readConfig(argv.config);
  argv = applyConfig(argv, config);
  let month = argv.month ?? displayPreviousMonth(new Date());
  let ctx = await cliContext(argv, config, fileRunStore(argv.runFile ?? `run-${month}.json`));
  if (argv.rebuildGenericStake) {
    let tx = await rebuildGenericStakeWithdrawal(ctx);
    console.log(`Rebuilt the generic stake withdrawal for the co-signer: ${tx.toCbor()}`);
  } else if (argv.stage == 1) {
    let tx = await runStage1(ctx, month);
    console.log(`Stage 1 done. Once the co-signer has signed and submitted the generic stake withdrawal, run stage 2: ${tx.toCbor()}`);
  } else if (argv.stage == 2) {
    await runStage2(ctx, argv.scooperCsv ? () => fs.readFileSync(argv.scooperCsv, "utf8") : undefined);
  } else {
    throw new Error("Expected --stage 1, --stage 2 or --rebuildGenericStake");
  }
  process.exit(0);
}
