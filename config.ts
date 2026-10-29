// Per-network settings for the revenue commands, so they can be run with
// --config instead of long flag lists. A config supplies defaults for the
// commands' flags; flags given on the command line win. Paths in a config are
// relative to the config file.
import * as fs from "node:fs";
import * as path from "node:path";

// One deployment of the protocol's scripts. The v3 blueprint also holds the
// settings, which the stable pools share, and the pool stake script.
interface SundaeProtocolConfig {
  poolAddress?: string,
  references?: string,
  blueprint?: string,
  // Idents of pools the withdrawals leave alone
  skipPools?: string[],
}

export interface NetworkConfig {
  network: "mainnet" | "preview",
  walletAddress?: string,
  // Receives what's withheld from the treasury
  withheldAddress?: string,
  // Treasury admin key hashes, comma separated
  signers?: string,
  sundaeAssetId?: string,
  v3?: SundaeProtocolConfig,
  stable?: SundaeProtocolConfig,
  genericStakeAddress?: string,
  poolStakeAddress?: string,
  preferredPoolsFile?: string,
  scooperAddressesFile?: string,
  delegatedScoopersFile?: string,
  tokenHoldersDestination?: string,
  yieldFarmingDestination?: string,
  txLogDir?: string,
}

const KEYS = [
  "network", "walletAddress", "withheldAddress", "signers", "sundaeAssetId", "v3", "stable",
  "genericStakeAddress", "poolStakeAddress", "preferredPoolsFile", "scooperAddressesFile",
  "delegatedScoopersFile", "tokenHoldersDestination", "yieldFarmingDestination", "txLogDir",
];
const PROTOCOL_KEYS = ["poolAddress", "references", "blueprint", "skipPools"];

export function readConfig(file: string): NetworkConfig {
  let config = JSON.parse(fs.readFileSync(file, "utf8"));
  checkKeys(config, KEYS, file);
  for (let protocol of ["v3", "stable"]) {
    if (config[protocol]) {
      checkKeys(config[protocol], PROTOCOL_KEYS, `${file} ${protocol}`);
    }
  }
  if (config.network != "mainnet" && config.network != "preview") {
    throw new Error(`${file}: network must be "mainnet" or "preview", not ${JSON.stringify(config.network)}`);
  }
  // Resolve paths against the config file's directory
  let dir = path.dirname(file);
  let resolve = (p: string | undefined) => p === undefined ? undefined : path.resolve(dir, p);
  let resolveProtocol = (protocol: SundaeProtocolConfig | undefined) =>
    protocol && { ...protocol, references: resolve(protocol.references), blueprint: resolve(protocol.blueprint) };
  return {
    ...config,
    v3: resolveProtocol(config.v3),
    stable: resolveProtocol(config.stable),
    preferredPoolsFile: resolve(config.preferredPoolsFile),
    scooperAddressesFile: resolve(config.scooperAddressesFile),
    delegatedScoopersFile: resolve(config.delegatedScoopersFile),
    txLogDir: resolve(config.txLogDir),
  };
}

// Catches misspelled keys, which would otherwise be silently ignored
function checkKeys(obj: object, known: string[], where: string) {
  for (let key of Object.keys(obj)) {
    if (!known.includes(key)) {
      throw new Error(`${where}: unknown key ${key}`);
    }
  }
}

// The command line flags with the config's defaults filled in
export function applyConfig(argv: Record<string, any>, config: NetworkConfig): Record<string, any> {
  if (argv.mainnet && config.network != "mainnet") {
    throw new Error(`--mainnet was given with a ${config.network} config`);
  }
  let protocol = argv.stable ? config.stable : config.v3;
  let defaults: Record<string, any> = {
    mainnet: config.network == "mainnet",
    walletAddress: config.walletAddress,
    withheldAddress: config.withheldAddress,
    signers: config.signers,
    sundaeAssetId: config.sundaeAssetId,
    blueprint: config.v3?.blueprint,
    stableBlueprint: config.stable?.blueprint,
    preferredPoolsFile: config.preferredPoolsFile,
    // The report and the payout read the same file under different flags
    scooperAddresses: config.scooperAddressesFile,
    addressesFile: config.scooperAddressesFile,
    delegatedScoopersFile: config.delegatedScoopersFile,
    tokenHoldersDestination: config.tokenHoldersDestination,
    yieldFarmingDestination: config.yieldFarmingDestination,
    txLogDir: config.txLogDir,
  };
  // Flags whose meaning depends on the command
  if (argv.autoWithdrawRewards) {
    defaults.poolAddress = protocol?.poolAddress;
    defaults.references = protocol?.references;
    defaults.skipPools = protocol?.skipPools;
  }
  if (argv.withdrawGenericStake) {
    defaults.stakeAddress = config.genericStakeAddress;
  }
  if (argv.withdrawPoolStakeRewards) {
    defaults.stakeAddress = config.poolStakeAddress;
  }
  let applied = { ...argv };
  for (let [key, value] of Object.entries(defaults)) {
    if (value !== undefined && applied[key] === undefined) {
      applied[key] = value;
    }
  }
  return applied;
}
