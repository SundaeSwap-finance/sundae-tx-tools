// The monthly revenue report, ported from compute-revenue-py's
// compute_revenue.py (gio format). Takes the scooper report CSV and the
// month's other revenue, and computes what each party is owed and how much
// must be withdrawn from where to pay it.
//
// Differences from the Python tool:
// - Several CSV rows for one scooper add up, rather than overwriting each other
// - totalRevenue includes the extra stableswap revenue, since the payments do
// - protocolFeesNeeded is never negative
// - Staking rewards are given, not queried, so the report can't depend on when
//   it was run

export interface ScooperRow {
  address: string,
  protocolFee: bigint,
  txFee: bigint,
}

// The scooper report CSV: a header row, then pub_key_hash, address,
// total_scoops, total_orders, total_protocol_fee, total_transaction_fee, ...
export function parseScooperCsv(csv: string): ScooperRow[] {
  let lines = csv.split(/\r?\n/).filter((line) => line.trim() != "");
  return lines.slice(1).map((line, i) => {
    let cols = line.split(",");
    if (cols.length < 6) {
      throw new Error(`Scooper report row ${i + 1} has ${cols.length} columns; expected at least 6`);
    }
    return { address: cols[1], protocolFee: BigInt(cols[4]), txFee: BigInt(cols[5]) };
  });
}

export interface ReportInput {
  rows: ScooperRow[],
  // Ticker -> addresses, as in scooper-addresses.json; rows are matched on "new"
  scooperAddresses: Record<string, { new?: string }>,
  // Scoopers to include even without any rows, and scoopers who are paid
  // their fees but no flat reward
  extraScoopers: string[],
  delegatedScoopers: string[],
  // Stake address -> staking rewards withdrawn this month
  stakingRewards: Record<string, bigint>,
  // Ada from the stable pool withdrawals, including converted tokens
  extraStableswapRevenue: bigint,
}

export interface ReportJson {
  rewards: Record<string, bigint>,
  feesPaid: Record<string, bigint>,
  delegatedScoopers: string[],
  totalProtocolRevenue: bigint,
  totalFees: bigint,
  totalScoopers: bigint,
  extraStableswapRevenue: bigint,
  totalRevenue: bigint,
  payments: {
    totalScooperPayout: bigint,
    totalPayout: bigint,
    yieldFarming: bigint,
    tokenHoldersFee: bigint,
    flat: bigint,
    stakingRewardsNeeded: bigint,
    protocolFeesNeeded: bigint,
  },
}

function min(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

export function buildReport(input: ReportInput): ReportJson {
  let feesPaid: Record<string, bigint> = {};
  let totalProtocolRevenue = 0n;
  let totalFees = 0n;
  for (let row of input.rows) {
    let name = Object.keys(input.scooperAddresses).find((ticker) => input.scooperAddresses[ticker].new == row.address);
    if (!name) {
      throw new Error(`Couldn't find an entry in the scooper addresses for ${row.address}`);
    }
    feesPaid[name] = (feesPaid[name] ?? 0n) + row.txFee;
    totalProtocolRevenue += row.protocolFee;
    totalFees += row.txFee;
  }
  for (let name of input.extraScoopers) {
    feesPaid[name] ??= 0n;
  }
  let totalScoopers = BigInt(Object.keys(feesPaid).length - input.delegatedScoopers.length);
  if (totalScoopers <= 0n) {
    throw new Error("No scoopers to pay a flat reward to");
  }

  let rewards = Object.values(input.stakingRewards).reduce((a, b) => a + b, 0n);
  let totalRevenue = totalProtocolRevenue + rewards + input.extraStableswapRevenue;

  // Scoopers get the lesser of 20k ADA + 10% and 50%; yield farming 35%; token
  // holders 10%
  let totalScooperPayout = min(20_000_000_000n + totalRevenue / 10n, totalRevenue / 2n);
  let yieldFarming = 35n * totalRevenue / 100n;
  let tokenHoldersFee = 10n * totalRevenue / 100n;
  let totalPayout = totalScooperPayout + yieldFarming + tokenHoldersFee;
  // Scoopers are reimbursed their fees, and split the rest evenly
  let flat = (totalScooperPayout - totalFees) / totalScoopers;

  // Staking rewards and stableswap revenue are already in the wallet; the rest
  // comes from the v3 protocol fees
  let stakingRewardsNeeded = min(totalPayout, rewards);
  let protocolFeesNeeded = totalPayout - stakingRewardsNeeded - input.extraStableswapRevenue;
  if (protocolFeesNeeded < 0n) {
    protocolFeesNeeded = 0n;
  }

  return {
    rewards: input.stakingRewards,
    feesPaid,
    delegatedScoopers: input.delegatedScoopers,
    totalProtocolRevenue,
    totalFees,
    totalScoopers,
    extraStableswapRevenue: input.extraStableswapRevenue,
    totalRevenue,
    payments: {
      totalScooperPayout,
      totalPayout,
      yieldFarming,
      tokenHoldersFee,
      flat,
      stakingRewardsNeeded,
      protocolFeesNeeded,
    },
  };
}

// The report as JSON, with amounts as plain integers like the Python tool's
export function reportToJson(report: ReportJson): string {
  return JSON.stringify(report, (_, value) => {
    if (typeof value != "bigint") {
      return value;
    }
    if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER)) {
      throw new Error(`${value} is too large to write as a JSON number`);
    }
    return Number(value);
  });
}
