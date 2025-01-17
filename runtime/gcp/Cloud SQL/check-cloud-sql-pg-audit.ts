import { sqladmin_v1 } from "@googleapis/sqladmin";
import { GoogleAuth } from "googleapis-common";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const POSTGRES_VERSIONS = [
	"POSTGRES_17",
	"POSTGRES_16",
	"POSTGRES_15",
	"POSTGRES_14",
	"POSTGRES_13",
	"POSTGRES_12",
	"POSTGRES_11",
	"POSTGRES_10",
	"POSTGRES_9_6"
];

function isPostgres(databaseVersion: string): boolean {
	return POSTGRES_VERSIONS.includes(databaseVersion);
}

async function checkCloudSqlPgAuditEnabled(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new sqladmin_v1.Sqladmin({ auth: new GoogleAuth() });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// List all Cloud SQL instances in the project
		const response = await client.instances.list({
			project: projectId
		});

		const instances = response.data.items || [];
		if (instances.length === 0) {
			results.checks.push({
				resourceName: "No SQL Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Cloud SQL instances found in the project"
			});
			return results;
		}

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
			if (!isPostgres(instance.databaseVersion)) {
				results.checks.push({
					resourceName: instance.name,
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "Not a PostgreSQL instance"
				});
				continue;
			}

			const databaseFlags = instance.settings?.databaseFlags || [];
			const pgAuditFlag = databaseFlags.find(flag => flag.name === "cloudsql.enable_pgaudit");

			results.checks.push({
				resourceName: instance.name,
				status: pgAuditFlag?.value === "on" ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message:
					pgAuditFlag?.value !== "on"
						? "PostgreSQL instance does not have cloudsql.enable_pgaudit flag enabled. To fix this, set the cloudsql.enable_pgaudit database flag to 'on' in the instance settings. See: https://cloud.google.com/sql/docs/postgres/flags"
						: undefined
			});
		}

		// If no PostgreSQL instances were found
		if (results.checks.length === 0) {
			results.checks.push({
				resourceName: "No PostgreSQL Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No PostgreSQL instances found in the project"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Project Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Cloud SQL instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkCloudSqlPgAuditEnabled(projectId);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure cloudsql.enable_pgaudit database flag is enabled for PostgreSQL instances",
	description:
		"PostgreSQL instances should have cloudsql.enable_pgaudit database flag enabled for comprehensive security logging and monitoring.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.8",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudSqlPgAuditEnabled,
	serviceName: "Cloud SQL",
	shortServiceName: "cloudsql"
} satisfies RuntimeTest;
