import { sqladmin_v1 } from "@googleapis/sqladmin";
import { GoogleAuth } from "googleapis-common";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const VALID_SEVERITY_LEVELS = new Set(["WARNING", "ERROR", "LOG", "FATAL", "PANIC"]);

async function checkPostgresLogMinMessages(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new sqladmin_v1.Sqladmin({ auth: new GoogleAuth() });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// List all SQL instances
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
			const logMinMessagesFlag = databaseFlags.find(flag => flag.name === "log_min_messages");

			if (!logMinMessagesFlag) {
				results.checks.push({
					resourceName: instance.name,
					status: ComplianceStatus.FAIL,
					message:
						"log_min_messages flag is not set. To fix this, set the log_min_messages database flag to 'WARNING' or higher severity ('ERROR', 'LOG', 'FATAL', 'PANIC') in the instance settings. See: https://cloud.google.com/sql/docs/postgres/flags"
				});
				continue;
			}

			const severity = logMinMessagesFlag.value?.toUpperCase();
			const isValidSeverity = severity && VALID_SEVERITY_LEVELS.has(severity);

			results.checks.push({
				resourceName: instance.name,
				status: isValidSeverity ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isValidSeverity
					? undefined
					: `log_min_messages is set to '${severity}', must be 'WARNING' or higher severity ('ERROR', 'LOG', 'FATAL', 'PANIC'). To fix this, set the log_min_messages database flag to 'WARNING' or higher severity in the instance settings. See: https://cloud.google.com/sql/docs/postgres/flags`
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Cloud SQL Check",
			status: ComplianceStatus.ERROR,
			message: `Error listing SQL instances: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkPostgresLogMinMessages(projectId);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure That the 'log_min_messages' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'WARNING' or Higher Severity",
	description:
		"Ensure that the 'log_min_messages' flag for Cloud SQL PostgreSQL Instance is set at minimum to 'WARNING' or higher severity level ('ERROR', 'LOG', 'FATAL', 'PANIC').",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.5",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkPostgresLogMinMessages,
	serviceName: "Cloud SQL",
	shortServiceName: "cloudsql"
} satisfies RuntimeTest;
