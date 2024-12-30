import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsBackupEnabled(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all RDS instances
		const response = await client.send(new DescribeDBInstancesCommand({}));

		if (!response.DBInstances || response.DBInstances.length === 0) {
			results.checks = [
				{
					resourceName: "No RDS Instances",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No RDS instances found in the region"
				}
			];
			return results;
		}

		// Check each RDS instance
		for (const instance of response.DBInstances) {
			if (!instance.DBInstanceIdentifier || !instance.DBInstanceArn) {
				results.checks.push({
					resourceName: "Unknown Instance",
					status: ComplianceStatus.ERROR,
					message: "RDS instance found without identifier or ARN"
				});
				continue;
			}

			const backupRetentionPeriod = instance.BackupRetentionPeriod || 0;
			const isCompliant = backupRetentionPeriod > 0;

			results.checks.push({
				resourceName: instance.DBInstanceIdentifier,
				resourceArn: instance.DBInstanceArn,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant
					? undefined
					: `RDS instance has backup retention period of ${backupRetentionPeriod} days (should be > 0)`
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking RDS instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsBackupEnabled(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure to Enable Backup and Recovery",
	description:
		"This rule checks if RDS instances have automated backups enabled with a retention period greater than 0 days.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_3.10",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsBackupEnabled,
	serviceName: "Amazon Relational Database Service"
} satisfies RuntimeTest;
