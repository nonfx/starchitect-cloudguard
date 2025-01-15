import { sqladmin_v1 } from "@googleapis/sqladmin";
import { GoogleAuth } from "googleapis-common";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const VALID_ERROR_LEVELS = ["error", "fatal", "panic"];

async function checkPostgresLogMinErrorStatement(
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
			const logMinErrorFlag = databaseFlags.find(flag => flag.name === "log_min_error_statement");

			if (!logMinErrorFlag) {
				results.checks.push({
					resourceName: instance.name,
					status: ComplianceStatus.FAIL,
					message:
						"log_min_error_statement flag is not set. To fix this, set the log_min_error_statement database flag to 'ERROR' or stricter ('FATAL', 'PANIC') in the instance settings. See: https://cloud.google.com/sql/docs/postgres/flags"
				});
				continue;
			}

			const isValidLevel =
				logMinErrorFlag.value && VALID_ERROR_LEVELS.includes(logMinErrorFlag.value);

			results.checks.push({
				resourceName: instance.name,
				status: isValidLevel ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isValidLevel
					? undefined
					: `log_min_error_statement must be set to 'ERROR' or stricter ('FATAL', 'PANIC'). Current value: ${logMinErrorFlag.value}. To fix this, set the log_min_error_statement database flag to 'ERROR' or stricter in the instance settings. See: https://cloud.google.com/sql/docs/postgres/flags`
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Project Check",
			status: ComplianceStatus.ERROR,
			message: `Error listing SQL instances: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkPostgresLogMinErrorStatement(projectId);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure That the 'log_min_error_statement' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'ERROR' or Stricter",
	description:
		"This rule ensures that PostgreSQL instances have log_min_error_statement set to 'ERROR' or stricter levels ('FATAL', 'PANIC') for proper error message classification and logging.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.6",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkPostgresLogMinErrorStatement,
	serviceName: "Cloud SQL",
	shortServiceName: "cloudsql"
} satisfies RuntimeTest;
