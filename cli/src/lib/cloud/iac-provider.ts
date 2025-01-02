import { Command, Flags } from "@oclif/core";

export abstract class CloudIacProvider extends Command {
	public static enableJsonFlag = true;
	static description = "Run security tests against Infrastructure as Code";

	static flags = {
		dir: Flags.directory({
			description: "Directory of your Infrastructure as Code",
			required: true
		}),
		format: Flags.string({
			description: "Output format",
			options: ["json", "stdout"],
			default: "stdout"
		})
	};

	async run(): Promise<void> {
		this.warn("This command is not yet implemented");
	}
}
