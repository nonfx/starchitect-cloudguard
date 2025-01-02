import { type Hook } from "@oclif/core";
import chalk from "chalk";

// https://github.com/oclif/core/issues/1284
const hook: Hook<"init"> = async function (opts) {
	opts.config.pjson.description = [
		"Starkit is a CLI to run tests against your Cloud accounts or your IAC files.",
		"Here are a few examples of commands you can run:\n",
		chalk.gray("# To run tests against your AWS account"),
		"$ starkit runtime aws\n",
		chalk.gray("# To view all available options for the AWS runtime checker"),
		"$ starkit runtime aws --help"
	].join("\n");
};

export default hook;
