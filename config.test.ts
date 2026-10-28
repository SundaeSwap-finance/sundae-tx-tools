import { describe, it, expect } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { applyConfig, readConfig } from "./config.ts";
import { sundaeAssetId } from "./index.ts";

const ROOT = path.dirname(new URL(import.meta.url).pathname);
const mainnet = readConfig(path.join(ROOT, "mainnet.config.json"));
const preview = readConfig(path.join(ROOT, "preview.config.json"));

const WALLET = "addr1v92m7sgckq0pc72xgldexa0lepe7gdwhxuq8k2kmcjxdh2skxa0m4";
const SIGNERS = "55bf4118b01e1c794647db9375ffc873e435d737007b2adbc48cdbaa";

function writeConfig(config: object): string {
  let dir = fs.mkdtempSync(path.join(os.tmpdir(), "config-test-"));
  let file = path.join(dir, "test.config.json");
  fs.writeFileSync(file, JSON.stringify(config));
  return file;
}

// The mainnet config should stand in for the flags the manual run (new-steps)
// passes to each command
describe("the mainnet config", () => {
  it("gives the stable withdrawal the stable pools", () => {
    let argv = applyConfig({ autoWithdrawRewards: true, stable: true, needed: 0 }, mainnet);
    expect(argv).toMatchObject({
      mainnet: true,
      walletAddress: WALLET,
      withheldAddress: WALLET,
      signers: SIGNERS,
      poolAddress: "addr1x9x70xsvzuvqqv9l7npksfwtd6vu4gq8h33j77y4vx3x64jrnxqnmtv3hdu2t6chcfhl2zzjh36a87nmd6dwsu3jenqskqe4x0",
      references: path.join(ROOT, "references-stable-mainnet"),
      blueprint: path.join(ROOT, "mainnet.blueprint.json"),
      stableBlueprint: path.join(ROOT, "plutus-stable-mainnet.json"),
    });
  });

  it("gives the v3 withdrawal the v3 pools", () => {
    let argv = applyConfig({ autoWithdrawRewards: true }, mainnet);
    expect(argv).toMatchObject({
      poolAddress: "addr1z8srqftqemf0mjlukfszd97ljuxdp44r372txfcr75wrz2auzrlrz2kdd83wzt9u9n9qt2swgvhrmmn96k55nq6yuj4qw992w9",
      references: path.join(ROOT, "references-mainnet"),
    });
  });

  it("gives each stake withdrawal its own stake address", () => {
    expect(applyConfig({ withdrawGenericStake: true }, mainnet).stakeAddress)
      .toBe("stake1ux7ppl339txknchp9j7zejs94g8yxt3aaejat22fsdzwf2ssw6paf");
    expect(applyConfig({ withdrawPoolStakeRewards: true }, mainnet).stakeAddress)
      .toBe("stake179penqfa4kgmk799avtuyml4ppftcawnlfakaxhgwgevesggrke2g");
  });

  it("gives the swap and payout the mainnet SUNDAE and destinations", () => {
    let argv = applyConfig({ doPayout: true }, mainnet);
    expect(sundaeAssetId(argv)).toBe("9a9693a9a37912a5097918f97918d15240c92ab729a0b7c4aa144d7753554e444145");
    expect(argv).toMatchObject({
      tokenHoldersDestination: "addr1q870hx86xk5qyt53za6vq578nqs6kd6cjssspna94u83vvkhy3954pmhklwxjz05vsx0qt4yw4a9275eldyrkp0c0hlqcjj7rf",
      yieldFarmingDestination: "addr1q9dn3wsrzuy62fu0lddzq8qzdyczqjle79p66cnydvf2lkwhy3954pmhklwxjz05vsx0qt4yw4a9275eldyrkp0c0hlq5ygnqp",
    });
  });

  it("gives the report and the payout the same scooper addresses", () => {
    let argv = applyConfig({}, mainnet);
    expect(argv.scooperAddresses).toBe(argv.addressesFile);
  });
});

describe("applyConfig", () => {
  it("lets flags on the command line override the config", () => {
    let argv = applyConfig({ withdrawGenericStake: true, stakeAddress: "stake1other", walletAddress: "addr1other" }, mainnet);
    expect(argv.stakeAddress).toBe("stake1other");
    expect(argv.walletAddress).toBe("addr1other");
  });

  it("runs a preview config on preview", () => {
    expect(applyConfig({}, preview).mainnet).toBe(false);
  });

  it("refuses --mainnet with a preview config", () => {
    expect(() => applyConfig({ mainnet: true }, preview)).toThrow(/--mainnet was given with a preview config/);
  });
});

describe("readConfig", () => {
  it("resolves paths against the config file's directory", () => {
    let file = writeConfig({ network: "preview", v3: { blueprint: "bp.json" }, stable: { references: "refs" } });
    let config = readConfig(file);
    expect(config.v3!.blueprint).toBe(path.join(path.dirname(file), "bp.json"));
    expect(config.stable!.references).toBe(path.join(path.dirname(file), "refs"));
  });

  it("refuses a misspelled key", () => {
    expect(() => readConfig(writeConfig({ network: "preview", walletAdress: "addr_test1" }))).toThrow(/unknown key walletAdress/);
    expect(() => readConfig(writeConfig({ network: "preview", v3: { poolAdress: "addr_test1" } }))).toThrow(/unknown key poolAdress/);
  });

  it("refuses an unknown network", () => {
    expect(() => readConfig(writeConfig({ network: "testnet" }))).toThrow(/network must be/);
  });
});

describe("sundaeAssetId", () => {
  it("has no default off mainnet", () => {
    expect(() => sundaeAssetId(applyConfig({}, preview))).toThrow(/sundaeAssetId/);
  });
});
