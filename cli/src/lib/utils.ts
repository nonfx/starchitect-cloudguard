import chalk from "chalk";

export function generatePrefilledCommand(
	baseCommandName: string,
	flags: Record<string, unknown>
): string {
	const flagStrings = Object.entries(flags).map(([flagName, flagValue]) => {
		if (flagValue === true) {
			return `--${flagName}`;
		}

		return `--${flagName}=${flagValue}`;
	});

	const command = `starkit ${baseCommandName} ${flagStrings.join(" ")}`;

	if (process.env.CI) {
		return command;
	} else {
		return chalk.bgGray.white(command);
	}
}
