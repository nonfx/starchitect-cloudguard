import { runCommand } from "@oclif/test";
import { expect } from "chai";

describe("runtime-test", () => {
	it("runs runtime-test cmd", async () => {
		const { stdout } = await runCommand("runtime-test");
		expect(stdout).to.contain("hello world");
	});

	it("runs runtime-test --name oclif", async () => {
		const { stdout } = await runCommand("runtime-test --name oclif");
		expect(stdout).to.contain("hello oclif");
	});
});
