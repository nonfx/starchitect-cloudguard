import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkAuroraBacktrackingCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DB clusters
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

		// Check each Aurora cluster
		for (const cluster of response.DBClusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			// Check if cluster is Aurora
			if (!cluster.Engine?.startsWith("aurora")) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "Not an Aurora cluster"
				});
				continue;
			}

			// Check if backtracking is enabled
			const hasBacktracking = cluster.BacktrackWindow && cluster.BacktrackWindow > 0;

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: hasBacktracking ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasBacktracking ? undefined : "Aurora cluster does not have backtracking enabled"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Aurora clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkAuroraBacktrackingCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Amazon Aurora clusters should have backtracking enabled",
	description:
		"This control checks whether Amazon Aurora clusters have backtracking enabled for point-in-time recovery capabilities.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.14",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAuroraBacktrackingCompliance
} satisfies RuntimeTest;
