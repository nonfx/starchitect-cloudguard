#!/usr/bin/env bun
/**
 * Script to run Regula OPA tests on all terraform policies.
 *
 * Usage:
 *   bun .scripts/run-opa-tests.ts [--filter <pattern>] [--verbose]
 *
 * Options:
 *   --filter <pat>   Only run tests matching the pattern (e.g., "aws/AWS Backup")
 *   --verbose        Show verbose output including test details
 *
 * Examples:
 *   bun .scripts/run-opa-tests.ts                          # Run all tests
 *   bun .scripts/run-opa-tests.ts --filter "AWS Lambda"    # Run only Lambda tests
 *   bun .scripts/run-opa-tests.ts --filter gcp             # Run only GCP tests
 */

import { spawnSync } from "child_process";
import { readdirSync, statSync } from "fs";
import { join, dirname } from "path";

const TERRAFORM_DIR = join(import.meta.dirname, "..", "terraform");

function findRegoFiles(dir: string): string[] {
	const results: string[] = [];

	function walk(currentDir: string) {
		const entries = readdirSync(currentDir);
		for (const entry of entries) {
			const fullPath = join(currentDir, entry);
			const stat = statSync(fullPath);
			if (stat.isDirectory()) {
				walk(fullPath);
			} else if (entry.endsWith(".rego")) {
				results.push(fullPath);
			}
		}
	}

	walk(dir);
	return results;
}

function findTestDirectories(baseDir: string): string[] {
	const dirs = new Set<string>();
	const regoFiles = findRegoFiles(baseDir);

	for (const file of regoFiles) {
		dirs.add(dirname(file));
	}

	return Array.from(dirs).sort();
}

interface TestResult {
	path: string;
	success: boolean;
	output: string;
	configsLoaded: number;
}

function runRegulaTest(dir: string): TestResult {
	const result: TestResult = {
		path: dir,
		success: false,
		output: "",
		configsLoaded: 0
	};

	const proc = spawnSync("npx", ["regula-wasi", "test", dir], {
		encoding: "utf-8",
		timeout: 120000,
		cwd: process.cwd()
	});

	result.output = (proc.stdout || "") + (proc.stderr || "");
	result.success = proc.status === 0;

	// Extract number of loaded configs
	const match = result.output.match(/Loaded (\d+) IaC configurations/);
	if (match) {
		result.configsLoaded = parseInt(match[1], 10);
	}

	return result;
}

async function main() {
	const args = process.argv.slice(2);
	const verbose = args.includes("--verbose");
	const filterIndex = args.indexOf("--filter");
	const filter = filterIndex !== -1 ? args[filterIndex + 1] : null;

	console.log("=== Regula OPA Test Runner ===\n");

	// Check regula-wasi version
	const versionProc = spawnSync("npx", ["regula-wasi", "version"], {
		encoding: "utf-8",
		timeout: 30000
	});

	if (versionProc.status !== 0) {
		console.error("Error: regula-wasi is not installed. Run: npm install --save-dev regula-wasi");
		process.exit(1);
	}

	const versionOutput = (versionProc.stdout || "") + (versionProc.stderr || "");
	const opaVersion = versionOutput.match(/OPA v([\d.]+)/)?.[1] || "unknown";
	console.log(`Using regula-wasi with OPA v${opaVersion}\n`);

	// Find all test directories
	let testDirs = findTestDirectories(TERRAFORM_DIR);

	if (filter) {
		testDirs = testDirs.filter(d => d.toLowerCase().includes(filter.toLowerCase()));
		console.log(`Filtering to ${testDirs.length} directories matching: ${filter}\n`);
	}

	console.log(`Found ${testDirs.length} test directories\n`);

	if (testDirs.length === 0) {
		console.log("No test directories found.");
		return;
	}

	const results: TestResult[] = [];
	let passed = 0;
	let failed = 0;
	let totalConfigs = 0;

	for (const dir of testDirs) {
		const relativePath = dir.replace(TERRAFORM_DIR + "/", "");
		process.stdout.write(`Testing: ${relativePath}... `);

		const result = runRegulaTest(dir);
		totalConfigs += result.configsLoaded;

		if (result.success) {
			console.log(`✓ PASS (${result.configsLoaded} configs)`);
			passed++;
		} else {
			console.log("✗ FAIL");
			if (verbose) {
				console.log(result.output);
			}
			failed++;
		}

		results.push(result);
	}

	console.log("\n=== Summary ===");
	console.log(`Directories: ${testDirs.length}`);
	console.log(`IaC Configs: ${totalConfigs}`);
	console.log(`Passed: ${passed}`);
	console.log(`Failed: ${failed}`);

	if (failed > 0) {
		console.log("\nFailed tests:");
		for (const result of results) {
			if (!result.success) {
				const relativePath = result.path.replace(TERRAFORM_DIR + "/", "");
				console.log(`  - ${relativePath}`);
			}
		}
		process.exit(1);
	}

	console.log("\n✓ All tests passed!");
}

main().catch(e => {
	console.error(e);
	process.exit(1);
});
