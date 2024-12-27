// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { runCommand } from "@oclif/test";

describe.skip("hello", () => {
	it("runs hello", async () => {
		const { stdout } = await runCommand("hello friend --from oclif");
		expect(stdout).to.contain("hello friend from oclif!");
	});
});
