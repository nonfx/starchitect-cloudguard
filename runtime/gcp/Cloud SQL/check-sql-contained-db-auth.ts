import { sqladmin_v1 } from "@googleapis/sqladmin";
import { GoogleAuth } from "googleapis-common";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const SQL_SERVER_VERSIONS = new Set([
	"SQLSERVER_2022_STANDARD",
	"SQLSERVER_2022_ENTERPRISE",
	"SQLSERVER_2022_EXPRESS",
	"SQLSERVER_2022_WEB",
	"SQLSERVER_2019_STANDARD",
	"SQLSERVER_2019_ENTERPRISE",
	"SQLSERVER_2019_EXPRESS",
	"SQLSERVER_2019_WEB",
	"SQLSERVER_2017_STANDARD",
	"SQLSERVER_2017_ENTERPRISE",
	"SQLSERVER_2017_EXPRESS",
	"SQLSERVER_2017_WEB"
]);

async function checkSqlContainedDbAuth(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new sqladmin_v1.Sqladmin({ auth: new GoogleAuth() });
	const results: ComplianceReport = {
		checks: []
	};

	try {
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

		for (const instance of instances) {
			if (!instance.name || !instance.databaseVersion) {
				results.checks.push({
					resourceName: instance.name || "Unknown Instance",
					status: ComplianceStatus.ERROR,
					message: "Instance missing name or database version"
				});
				continue;
			}

			// Skip non-SQL Server instances
			if (!SQL_SERVER_VERSIONS.has(instance.databaseVersion)) {
				results.checks.push({
					resourceName: instance.name,
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "Not a SQL Server instance"
				});
				continue;
			}

			const databaseFlags = instance.settings?.databaseFlags || [];
			const containedDbAuthFlag = databaseFlags.find(
				flag => flag.name === "contained database authentication"
			);

			const isEnabled = containedDbAuthFlag?.value === "on";
			results.checks.push({
				resourceName: instance.name,
				status: isEnabled ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: isEnabled
					? "Contained database authentication is enabled. To fix this, set the 'contained database authentication' database flag to 'off' in the instance settings for better security. See: https://cloud.google.com/sql/docs/sqlserver/flags"
					: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Project Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking SQL instances: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const projectId = process.env.GCP_PROJECT_ID;
	const results = await checkSqlContainedDbAuth(projectId);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure That the 'contained database authentication' Database Flag for Cloud SQL SQL Server Instance Is Not Set to 'on'",
	description:
		"It is recommended not to set contained database authentication database flag for Cloud SQL on the SQL Server instance to on.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.3.7",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkSqlContainedDbAuth,
	serviceName: "Cloud SQL",
	shortServiceName: "cloudsql"
} satisfies RuntimeTest;