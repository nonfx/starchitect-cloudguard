import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocDBDeletionProtection(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new DocDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DocumentDB clusters
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

		// Check each cluster for deletion protection
		for (const cluster of response.DBClusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: cluster.DeletionProtection ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: cluster.DeletionProtection
					? undefined
					: "DocumentDB cluster does not have deletion protection enabled"
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
	const results = await checkDocDBDeletionProtection(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Amazon DocumentDB clusters should have deletion protection enabled",
	description:
		"Amazon DocumentDB clusters must enable deletion protection to prevent accidental or unauthorized database deletion.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_DocumentDB.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDocDBDeletionProtection,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
