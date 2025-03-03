import { type Hook } from "@oclif/core";
import { mkdir, writeFile } from "fs/promises";
import { join } from "path";
import { homedir } from "os";

const hook: Hook<"init"> = async function () {
	try {
		const starkitDir = join(homedir(), ".local", "share", "starkit");
		await mkdir(starkitDir, { recursive: true });

		const channelFile = join(starkitDir, "channel");
		await writeFile(channelFile, "stable", { flag: "wx" }); // wx flag means write only if file doesn't exist
	} catch (error: unknown) {
		// Ignore error if file already exists
		if (error instanceof Error && "code" in error && error.code !== "EEXIST") {
			console.error("Warning: Failed to setup starkit channel", error);
		}
	}
};

export default hook;
