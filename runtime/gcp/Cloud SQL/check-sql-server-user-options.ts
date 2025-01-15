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

async function checkSqlServerUserOptions(
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
			const userOptionsFlag = databaseFlags.find(flag => flag.name === "user options");

			const isCompliant = !userOptionsFlag;
			results.checks.push({
				resourceName: instance.name,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant
					? undefined
					: "SQL Server instance has user options database flag configured. To fix this, remove the 'user options' database flag from the instance settings to maintain secure default query processing settings. See: https://cloud.google.com/sql/docs/sqlserver/flags"
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
	const results = await checkSqlServerUserOptions(projectId);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure That the 'user options' Database Flag for Cloud SQL SQL Server Instance Is Not Configured",
	description:
		"It is recommended that the 'user options' database flag for Cloud SQL SQL Server instance should not be configured to maintain secure default query processing settings.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.3.4",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkSqlServerUserOptions,
	serviceName: "Cloud SQL",
	shortServiceName: "cloudsql"
} satisfies RuntimeTest;
