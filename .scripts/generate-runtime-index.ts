import { Glob } from "bun";
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

generateIndexFor("aws");
generateIndexFor("gcp");
generateIndexFor("azure");

function generateIndexFor(cloud: string) {
	const runtimeDir = resolve(import.meta.dir, "../runtime", cloud);

	if (!existsSync(runtimeDir)) {
		console.warn(`⚠️ No runtime directory found for ${cloud} at ${runtimeDir}`);
		return;
	}

	const runtimeGlob = new Glob("**/*.ts");

	const results = runtimeGlob.scanSync({
		cwd: runtimeDir,
		onlyFiles: true
	});

	const runtimeFiles = Array.from(results).filter(file => {
		return !file.endsWith(".test.ts") && !file.endsWith("index.ts") && !file.includes(" copy");
	});

	runtimeFiles.sort();

	if (runtimeFiles.length === 0) {
		console.warn(`⚠️ No runtime files found in ${runtimeDir}`);
		return;
	}

	const imports = runtimeFiles.map((file, idx) => {
		return `import import${idx} from "./${file.replace(/\.[^/.]+$/, "")}.js";`;
	});

	const outfile = resolve(runtimeDir, "index.ts");

	writeFileSync(
		outfile,
		`
/* eslint-disable */
/**
 * This file is auto-generated by the "npm run generate-runtime-index" command.
 * Do not modify this file directly.
 */
${imports.join("\n")}

export default [
    ${runtimeFiles.map((_, idx) => `import${idx}`).join(",\n    ")}
];
`.trim()
	);

	console.info(`✅ Generated runtime index for ${runtimeFiles.length} tests for ${cloud}.`);
}
