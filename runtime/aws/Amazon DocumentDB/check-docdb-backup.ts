import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocumentDBBackupCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new DocDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new DescribeDBClustersCommand({});
		const response = await client.send(command);

		if (!response.DBClusters || response.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No DocumentDB Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No DocumentDB clusters found in the region"
				}
			];
			return results;
		}

		for (const cluster of response.DBClusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			const checks = [];

			// Check backup retention period
			if (!cluster.BackupRetentionPeriod || cluster.BackupRetentionPeriod < 1) {
				checks.push("Backup retention period not properly configured");
			}

			// Check availability zones
			if (!cluster.AvailabilityZones || cluster.AvailabilityZones.length < 2) {
				checks.push("Insufficient availability zones configured");
			}

			// Check deletion protection
			if (!cluster.DeletionProtection) {
				checks.push("Deletion protection not enabled");
			}

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: checks.length === 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: checks.length > 0 ? checks.join("; ") : undefined
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DocumentDB clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDocumentDBBackupCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure to Implement Backup and Disaster Recovery",
	description:
		"Set up automated backups for your DocumentDB instances to ensure data durability and recoverability. Consider implementing a disaster recovery plan that includes data replication across different availability zones or regions.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.9",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDocumentDBBackupCompliance,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
