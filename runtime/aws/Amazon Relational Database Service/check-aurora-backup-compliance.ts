import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAuroraBackupCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Aurora clusters
		const command = new DescribeDBClustersCommand({});
		const response = await client.send(command);

		if (!response.DBClusters || response.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No Aurora Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Aurora clusters found in the region"
				}
			];
			return results;
		}

		// Check each cluster's backup configuration
		for (const cluster of response.DBClusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			const retentionPeriod = cluster.BackupRetentionPeriod;

			// Check if backup retention period is within valid range (1-35 days)
			const isValid =
				retentionPeriod !== undefined && retentionPeriod >= 1 && retentionPeriod <= 35;

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: isValid ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isValid
					? undefined
					: `Invalid backup retention period: ${retentionPeriod}. Should be between 1 and 35 days.`
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Aurora Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Aurora clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAuroraBackupCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Automatic Backups and Retention Policies are configured",
	description:
		"Backups help protect your data from accidental loss or database failure. With Amazon Aurora, you can turn on automatic backups and specify a retention period. The backups include a daily snapshot of the entire DB instance and transaction logs",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_2.10",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkAuroraBackupCompliance,
	serviceName: "Amazon Relational Database Service"
} satisfies RuntimeTest;
