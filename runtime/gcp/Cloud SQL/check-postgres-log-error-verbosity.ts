import { sqladmin_v1 } from "@googleapis/sqladmin";
import { GoogleAuth } from "googleapis-common";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkPostgresLogErrorVerbosity(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new sqladmin_v1.Sqladmin({ auth: new GoogleAuth() });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get list of all SQL instances
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

			// Skip non-PostgreSQL instances
			if (!instance.databaseVersion.startsWith("POSTGRES")) {
				results.checks.push({
					resourceName: instance.name,
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "Not a PostgreSQL instance"
				});
				continue;
			}

			const databaseFlags = instance.settings?.databaseFlags || [];
			const verbosityFlag = databaseFlags.find(flag => flag.name === "log_error_verbosity");

			const isCompliant = verbosityFlag?.value === "default";

			results.checks.push({
				resourceName: instance.name,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant
					? undefined
					: "log_error_verbosity flag is not set to 'DEFAULT'. To fix this, set the log_error_verbosity database flag to 'DEFAULT' in the instance settings. See: https://cloud.google.com/sql/docs/postgres/flags"
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
		return results;
	}

	return results;
}

if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkPostgresLogErrorVerbosity(projectId);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure That the 'log_error_verbosity' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'DEFAULT'",
	description:
		"Ensure PostgreSQL log_error_verbosity flag is set to 'DEFAULT' or stricter for proper error message logging in Cloud SQL instances.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.1",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkPostgresLogErrorVerbosity,
	serviceName: "Cloud SQL",
	shortServiceName: "cloudsql"
} satisfies RuntimeTest;
