import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";

import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkNeptuneDeletionProtection(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new NeptuneClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Neptune DB clusters
		const command = new DescribeDBClustersCommand({});
		const response = await client.send(command);

		if (!response.DBClusters || response.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No Neptune Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Neptune DB clusters found in the region"
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
					: "Neptune DB cluster does not have deletion protection enabled"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Neptune Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Neptune clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkNeptuneDeletionProtection(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Neptune DB clusters should have deletion protection enabled",
	description:
		"This control checks if Neptune DB clusters have deletion protection enabled to prevent accidental or unauthorized database deletion.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Neptune.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkNeptuneDeletionProtection,
	serviceName: "Amazon Relational Database Service",
	shortServiceName: "rds"
} satisfies RuntimeTest;
