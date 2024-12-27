import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkRdsClusterMultiAz(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all RDS clusters
		const command = new DescribeDBClustersCommand({});
		const response = await client.send(command);

		if (!response.DBClusters || response.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No RDS Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No RDS clusters found in the region"
				}
			];
			return results;
		}

		// Check each cluster for multi-AZ configuration
		for (const cluster of response.DBClusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			// Check if cluster has multiple AZs configured
			const hasMultipleAZs = cluster.AvailabilityZones && cluster.AvailabilityZones.length > 1;

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: hasMultipleAZs ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasMultipleAZs
					? undefined
					: "RDS cluster is not configured with multiple Availability Zones"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking RDS clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsClusterMultiAz(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS DB clusters should be configured for multiple Availability Zones",
	description:
		"This control checks whether RDS DB clusters are configured with multiple Availability Zones for high availability and automated failover capabilities.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.15",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsClusterMultiAz
} satisfies RuntimeTest;
