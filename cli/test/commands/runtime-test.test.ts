// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { runCommand } from "@oclif/test";

describe.skip("runtime-test", () => {
	it("runs runtime-test cmd", async () => {
		const { stdout } = await runCommand("runtime-test");
		expect(stdout).to.contain("hello world");
	});

	it("runs runtime-test --name oclif", async () => {
		const { stdout } = await runCommand("runtime-test --name oclif");
		expect(stdout).to.contain("hello oclif");
	});
});
