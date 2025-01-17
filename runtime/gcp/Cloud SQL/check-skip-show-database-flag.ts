import { sqladmin_v1 } from "@googleapis/sqladmin";
import { GoogleAuth } from "googleapis-common";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkSkipShowDatabaseFlag(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new sqladmin_v1.Sqladmin({ auth: new GoogleAuth() });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// List all SQL instances in the project
		const response = await client.instances.list({
			project: projectId
		});

		const instances = response.data.items || [];
		if (instances.length === 0) {
			results.checks = [
				{
					resourceName: "No SQL Instances",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Cloud SQL instances found in the project"
				}
			];
			return results;
		}

		// Check each instance
		for (const instance of instances) {
			if (!instance.name || !instance.databaseVersion) {
				results.checks.push({
					resourceName: instance.name || "Unknown Instance",
					status: ComplianceStatus.ERROR,
					message: "Instance missing name or database version"
				});
				continue;
			}

			// Only check MySQL instances
			if (!instance.databaseVersion.toLowerCase().includes("mysql")) {
				results.checks.push({
					resourceName: instance.name,
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "Not a MySQL instance"
				});
				continue;
			}

			// Check database flags
			const databaseFlags = instance.settings?.databaseFlags || [];
			const skipShowFlag = databaseFlags.find(flag => flag.name === "skip_show_database");

			const isCompliant = skipShowFlag?.value === "on";
			results.checks.push({
				resourceName: instance.name,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant
					? undefined
					: "skip_show_database flag is not set to 'on'. To fix this, set the skip_show_database database flag to 'on' in the instance settings to prevent unauthorized users from viewing databases. See: https://cloud.google.com/sql/docs/mysql/flags"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Project Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking SQL instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkSkipShowDatabaseFlag(projectId);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure That the 'skip_show_database' Database Flag for Cloud SQL MySQL Instance Is Set to 'on'",
	description:
		"It is recommended to set skip_show_database database flag for Cloud SQL MySQL instance to on to prevent unauthorized users from viewing databases using SHOW DATABASES statement.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.1.2",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkSkipShowDatabaseFlag,
	serviceName: "Cloud SQL",
	shortServiceName: "cloudsql"
} satisfies RuntimeTest;
