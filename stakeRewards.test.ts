import { describe, it, expect, beforeEach } from "bun:test";
import * as crypto from "node:crypto";
import { Hash28ByteBase16, HexBlob, NetworkId, PlutusData, Transaction } from "@blaze-cardano/core";
import { Core } from "@blaze-cardano/sdk";
import {
  POOL_STAKE_TREASURY_AMOUNT,
  makeChangeUtxos,
  withdrawGenericStake,
  withdrawPoolStakeRewards,
  type RewardBalance,
} from "./index.ts";
import { decodeSettingsDatum, decoder, encodeSettingsDatum, withEncoderHex } from "./codec.ts";
import { fromHex } from "./util.ts";
import { STABLE_TOKEN, blueprint, makeWorld, type World } from "./testFixtures.ts";

// These tests run the change, generic stake and pool stake steps against an
// emulated ledger. The emulator checks that a withdrawal takes exactly the
// reward balance, and that the stake credential witnessed it.

function randomAddress(): Core.Address {
  return Core.Address.fromBytes(HexBlob("60" + crypto.randomBytes(28).toString("hex")));
}

function retry(overrides: { approve?: (tx: Transaction) => Promise<boolean> } = {}) {
  return {
    approve: overrides.approve ?? (async () => true),
    maxAttempts: 3,
    retryDelayMs: 0,
    confirmationTimeoutMs: 0,
  };
}

// Reads balances straight from the emulator, as Blockfrost would from the chain
function emulatorRewardBalance(world: World): RewardBalance {
  return async (stakeAddress) => world.emulator.accounts.get(stakeAddress) ?? 0n;
}

// Plain wallet utxos
function walletUtxos(world: World): Core.TransactionUnspentOutput[] {
  return world.emulator.utxos().filter((u) =>
    u.output().address().toBytes() == world.wallet.toBytes() && !u.output().scriptRef() && !u.output().datum());
}

describe("makeChangeUtxos", () => {
  let world: World;

  beforeEach(async () => {
    world = await makeWorld();
  });

  function run(count: bigint, amount: bigint, overrides: { retry?: any } = {}) {
    return makeChangeUtxos({
      blaze: world.blaze,
      provider: world.provider,
      walletAddress: world.wallet,
      count,
      amount,
      retry: "retry" in overrides ? overrides.retry : retry(),
      txLogDir: "",
    });
  }

  it("splits wallet funds into ada-only outputs and returns them", async () => {
    let made = await run(3n, 10_000_000n);

    expect(made.length).toBe(3);
    let onLedger = new Set(walletUtxos(world).map((u) => `${u.input().transactionId()}#${u.input().index()}`));
    for (let utxo of made) {
      expect(onLedger.has(`${utxo.input().transactionId()}#${utxo.input().index()}`)).toBe(true);
      expect(utxo.output().amount().coin()).toBe(10_000_000n);
      expect(utxo.output().amount().multiasset()?.size ?? 0).toBe(0);
    }
  });

  it("collects enough to pay the fee when the outputs use up whole utxos", async () => {
    // The wallet's change is 5 x 20 ADA, so 4 x 20 ADA needs a fifth input
    let made = await run(4n, 20_000_000n);
    expect(made.length).toBe(4);
  });

  it("keeps the tokens in the utxos it spends", async () => {
    // Leave the token-holding utxo as the only way to fund the outputs
    for (let utxo of walletUtxos(world)) {
      world.emulator.removeUtxo(utxo.input());
    }
    let tokens = new Core.TransactionUnspentOutput(
      new Core.TransactionInput(Core.TransactionId(crypto.randomBytes(32).toString("hex")), 0n),
      new Core.TransactionOutput(world.wallet, new Core.Value(50_000_000n, new Map([[STABLE_TOKEN, 7n]]))),
    );
    world.emulator.addUtxo(tokens);

    await run(2n, 10_000_000n);
    let held = walletUtxos(world).reduce((n, u) => n + (u.output().amount().multiasset()?.get(STABLE_TOKEN) ?? 0n), 0n);
    expect(held).toBe(7n);
  });

  it("builds a balanced transaction without submitting it in a dry run", async () => {
    let made = await run(2n, 10_000_000n, { retry: undefined });
    expect(made.length).toBe(2);
    expect(world.provider.submissions.length).toBe(0);
  });
});

describe("withdrawGenericStake", () => {
  let world: World;
  let stakeKey: Core.Ed25519PrivateKey;
  let stakeAddress: Core.RewardAccount;

  beforeEach(async () => {
    world = await makeWorld();
    stakeKey = Core.Ed25519PrivateKey.fromNormalBytes(crypto.randomBytes(32));
    let hash = (await stakeKey.toPublic()).hash().hex();
    stakeAddress = Core.RewardAccount.fromCredential({ type: Core.CredentialType.KeyHash, hash: Hash28ByteBase16(hash) }, NetworkId.Testnet);
    world.emulator.accounts.set(stakeAddress, 1_234_000_000n);
  });

  function run(overrides: { stakeKey?: Core.Ed25519PrivateKey | undefined, retry?: any } = {}) {
    return withdrawGenericStake({
      blaze: world.blaze,
      provider: world.provider,
      walletAddress: world.wallet,
      stakeAddress,
      rewardBalance: emulatorRewardBalance(world),
      stakeKey: "stakeKey" in overrides ? overrides.stakeKey : stakeKey,
      retry: "retry" in overrides ? overrides.retry : retry(),
      txLogDir: "",
    });
  }

  it("withdraws the whole balance into the wallet and reports it", async () => {
    let before = walletUtxos(world).reduce((n, u) => n + u.output().amount().coin(), 0n);
    let { tx, withdrawn } = await run();

    expect(withdrawn).toBe(1_234_000_000n);
    expect(world.emulator.accounts.get(stakeAddress)).toBe(0n);
    let after = walletUtxos(world).reduce((n, u) => n + u.output().amount().coin(), 0n);
    expect(after).toBe(before + withdrawn - tx.body().fee());
  });

  it("withdraws the new balance when it changes between attempts", async () => {
    // As if an epoch passed after the first attempt was built: the ledger
    // rejects it, and the retry withdraws the new balance
    let approvals = 0;
    let { withdrawn } = await run({
      retry: retry({
        approve: async () => {
          if (approvals++ == 0) {
            world.emulator.accounts.set(stakeAddress, 1_300_000_000n);
          }
          return true;
        },
      }),
    });

    expect(withdrawn).toBe(1_300_000_000n);
    expect(world.emulator.accounts.get(stakeAddress)).toBe(0n);
  });

  it("builds the withdrawal for the stake key's holder to co-sign in a dry run", async () => {
    let { tx, withdrawn } = await run({ stakeKey: undefined, retry: undefined });

    expect(withdrawn).toBe(1_234_000_000n);
    expect(tx.body().withdrawals()?.get(stakeAddress)).toBe(1_234_000_000n);
    expect(tx.witnessSet().vkeys()?.size() ?? 0).toBe(0);
    expect(world.provider.submissions.length).toBe(0);
  });

  it("refuses to submit without the stake key", async () => {
    await expect(run({ stakeKey: undefined })).rejects.toThrow(/without the stake key/);
    expect(world.provider.submissions.length).toBe(0);
  });

  it("refuses an empty balance", async () => {
    world.emulator.accounts.set(stakeAddress, 0n);
    await expect(run()).rejects.toThrow(/No rewards to withdraw/);
    expect(world.provider.submissions.length).toBe(0);
  });
});

// Replace the settings with ones that let the treasury admin withhold the
// given fraction of a pool stake withdrawal
function setTreasuryAllowance(world: World, numerator: bigint, denominator: bigint) {
  let settings = world.emulator.utxos().find((u) => u.output().address().getProps().paymentPart?.hash == blueprint.settingsSpend.hash)!;
  let datum = decodeSettingsDatum(decoder(fromHex(settings.output().datum()!.asInlineData()!.toCbor())));
  datum.treasuryAllowance = { numerator, denominator };
  let output = new Core.TransactionOutput(settings.output().address(), settings.output().amount());
  output.setDatum(Core.Datum.newInlineData(PlutusData.fromCbor(HexBlob(withEncoderHex(encodeSettingsDatum, datum)))));
  world.emulator.removeUtxo(settings.input());
  world.emulator.addUtxo(new Core.TransactionUnspentOutput(settings.input(), output));
}

describe("withdrawPoolStakeRewards", () => {
  let world: World;
  let stakeAddress: Core.RewardAccount;
  let withheldAddress: Core.Address;

  beforeEach(async () => {
    world = await makeWorld();
    // As on mainnet, the treasury admin may withhold everything
    setTreasuryAllowance(world, 1n, 1n);
    stakeAddress = Core.RewardAccount.fromCredential({ type: Core.CredentialType.ScriptHash, hash: Hash28ByteBase16(blueprint.poolStake.hash) }, NetworkId.Testnet);
    world.emulator.accounts.set(stakeAddress, 100_000_000n);
    withheldAddress = randomAddress();
  });

  function run(overrides: { retry?: any } = {}) {
    return withdrawPoolStakeRewards({
      blaze: world.blaze,
      provider: world.provider,
      walletAddress: world.wallet,
      stakeAddress,
      rewardBalance: emulatorRewardBalance(world),
      blueprint,
      signers: world.signer,
      withheldAddress,
      retry: "retry" in overrides ? overrides.retry : retry(),
      txLogDir: "",
    });
  }

  // Coin paid to the treasury (the fixture settings' treasury is the wallet's
  // key address, paid with a Void datum) and to the withheld address
  function split(tx: Transaction): { treasury: bigint[], withheld: bigint[] } {
    let outputs = tx.body().outputs();
    return {
      treasury: outputs.filter((o) => o.address().toBytes() == world.wallet.toBytes() && o.datum()?.asInlineData()?.toCbor() == "d87980").map((o) => o.amount().coin()),
      withheld: outputs.filter((o) => o.address().toBytes() == withheldAddress.toBytes()).map((o) => o.amount().coin()),
    };
  }

  it("pays the treasury a flat 2 ADA and the rest to the withheld address", async () => {
    let { tx, withdrawn, withheld } = await run();

    expect(withdrawn).toBe(100_000_000n);
    expect(withheld).toBe(98_000_000n);
    expect(world.emulator.accounts.get(stakeAddress)).toBe(0n);
    expect(split(tx)).toEqual({ treasury: [2_000_000n], withheld: [98_000_000n] });
  });

  it("pays the treasury more when the allowance requires it", async () => {
    // The fixture's original settings: withhold at most 1/10
    setTreasuryAllowance(world, 1n, 10n);
    let { tx, withheld } = await run();

    expect(withheld).toBe(10_000_000n);
    expect(split(tx)).toEqual({ treasury: [90_000_000n], withheld: [10_000_000n] });
  });

  it("pays the treasury a remainder too small for an output of its own", async () => {
    world.emulator.accounts.set(stakeAddress, 2_500_000n);
    let { tx, withheld } = await run();

    expect(withheld).toBe(0n);
    expect(split(tx)).toEqual({ treasury: [2_500_000n], withheld: [] });
  });

  it("leaves a balance under 2 ADA for next month", async () => {
    world.emulator.accounts.set(stakeAddress, POOL_STAKE_TREASURY_AMOUNT - 1n);
    await expect(run()).rejects.toThrow(/leave it for next month/);
    expect(world.provider.submissions.length).toBe(0);
  });

  it("refuses an empty balance", async () => {
    world.emulator.accounts.set(stakeAddress, 0n);
    await expect(run()).rejects.toThrow(/No rewards to withdraw/);
  });

  it("builds a balanced transaction without submitting it in a dry run", async () => {
    let { tx } = await run({ retry: undefined });
    expect(tx.body().fee()).toBeGreaterThan(0n);
    expect(world.provider.submissions.length).toBe(0);
    expect(world.emulator.accounts.get(stakeAddress)).toBe(100_000_000n);
  });
});
