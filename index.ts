import minimist from "minimist";
import * as builder from "./builder.ts";

let argv = minimist(process.argv.slice(2));
if (argv.buildUpdateFeeManager) {
  await builder.updateFeeManager(argv);
} else if (argv.prepareUpdate) {
  builder.prepareUpdate(argv);
} else if (argv.signMessage) {
  await builder.signMessage(argv);
} else if (argv.makeRedeemer) {
  await builder.makeRedeemer(argv);
} else if (argv.updateAllPoolStakeCredentials) {
  await builder.updateAllPoolStakeCredentials(argv);
} else if (argv.updateSinglePoolStakeCredential) {
  await builder.updateSinglePoolStakeCredential(argv);
} else if (argv.registerStakeAddress) {
  await builder.registerStakeAddress(argv);
} else if (argv.debugConditionedScoop) {
  await builder.debugConditionedScoop(argv);
} else if (argv.autoWithdrawRewards) {
  let { blaze, provider } = await builder.setupBlaze(argv);
  let opts = builder.makeAutoWithdrawOptions(argv, blaze, provider);
  await builder.autoWithdrawRewards(opts);
} else if (argv.testAutoWithdraw) {
  await builder.testAutoWithdraw(argv);
} else if (argv.doPayouts) {
  await builder.payouts(argv);
} else if (argv.doPayout) {
  await builder.doPayout(argv);
} else if (argv.makeChangeUtxos) {
  await builder.makeChangeUtxos(argv);
} else if (argv.withdrawGenericStake) {
  await builder.withdrawGenericStake(argv);
} else if (argv.withdrawPoolStakeRewards) {
  await builder.withdrawPoolStakeRewards(argv);
}

process.exit(0);
