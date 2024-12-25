import { runCommand } from "@oclif/test";

describe.skip("hello world", () => {
	it("runs hello world cmd", async () => {
		const { stdout } = await runCommand("hello world");
		expect(stdout).to.contain("hello world!");
	});
});
