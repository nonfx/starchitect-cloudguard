import { sqladmin_v1 } from "@googleapis/sqladmin";
import { GoogleAuth } from "googleapis-common";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudSqlLocalInfileFlag(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new sqladmin_v1.Sqladmin({ auth: new GoogleAuth() });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get list of all instances
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
			const localInfileFlag = databaseFlags.find(
				(flag: sqladmin_v1.Schema$DatabaseFlags) => flag.name === "local_infile"
			);

			const isCompliant = localInfileFlag?.value === "off";

			results.checks.push({
				resourceName: instance.name,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant
					? undefined
					: "local_infile flag is not set to 'off'. To fix this, set the local_infile database flag to 'off' in the instance settings. See: https://cloud.google.com/sql/docs/mysql/flags#setting_a_database_flag"
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
	const projectId = process.env.GOOGLE_CLOUD_PROJECT;
	const results = await checkCloudSqlLocalInfileFlag(projectId);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure That the 'Local_infile' Database Flag for Cloud SQL MySQL Instance Is Set to 'Off'",
	description:
		"It is recommended to set the local_infile database flag for a Cloud SQL MySQL instance to off to prevent unauthorized local data loading.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.1.3",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	execute: checkCloudSqlLocalInfileFlag,
	serviceName: "Cloud SQL",
	shortServiceName: "cloudsql"
} satisfies RuntimeTest;
