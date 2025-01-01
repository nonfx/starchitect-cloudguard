import { Glob } from "bun";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

updateServiceName("aws");
updateServiceName("gcp");
updateServiceName("azure");

function updateServiceName(cloud: string) {
	const runtimeDir = resolve(import.meta.dir, "../runtime", cloud);

	if (!existsSync(runtimeDir)) {
		return;
	}

	const runtimeGlob = new Glob("**/*.ts");

	const results = runtimeGlob.scanSync({
		absolute: true,
		cwd: runtimeDir,
		onlyFiles: true
	});

	const runtimeFiles = Array.from(results).filter(file => {
		return !file.endsWith(".test.ts") && !file.endsWith("index.ts") && !file.includes(" copy");
	});

	runtimeFiles.sort();

	if (runtimeFiles.length === 0) {
		return;
	}

	runtimeFiles.forEach(file => {
		const fileContents = readFileSync(file, "utf-8");
		const serviceName = file.split("/").at(-2);

		if (!serviceName) {
			console.error(`No service name found for ${file}`);
			return;
		}

		if (fileContents.includes("serviceName:")) {
			console.error(`Service name already exists in ${file}`);
			return;
		}

		const indexOfExport = fileContents.indexOf("} satisfies RuntimeTest");

		if (indexOfExport === -1) {
			console.error(`No export found in ${file}`);
			return;
		}

		const updatedFileContents =
			fileContents.slice(0, indexOfExport) +
			`,\n serviceName: "${serviceName}",\n` +
			fileContents.slice(indexOfExport);

		writeFileSync(file, updatedFileContents);

		console.log(`✅ Updated service name in ${file}`);
	});
}
