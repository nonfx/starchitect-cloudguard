import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocDBBackupWindowCompliance(
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
			if (!cluster.DBClusterIdentifier) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier"
				});
				continue;
			}

			const hasBackupWindow =
				cluster.PreferredBackupWindow && cluster.PreferredBackupWindow.trim() !== "";

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: hasBackupWindow ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasBackupWindow
					? undefined
					: "DocumentDB cluster does not have a backup window configured"
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
	const results = await checkDocDBBackupWindowCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure to Configure Backup Window",
	description: "",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.10",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDocDBBackupWindowCompliance,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
