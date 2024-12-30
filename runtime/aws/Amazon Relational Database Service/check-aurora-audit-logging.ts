import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAuroraAuditLoggingCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const rdsClient = new RDSClient({ region });
	const cloudTrailClient = new CloudTrailClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check CloudTrail configuration
		const trailsResponse = await cloudTrailClient.send(new DescribeTrailsCommand({}));
		const trails = trailsResponse.trailList || [];

		const hasValidCloudTrail = trails.some(
			trail => trail.IsMultiRegionTrail && trail.IncludeGlobalServiceEvents
		);

		// Check Aurora clusters
		const clustersResponse = await rdsClient.send(
			new DescribeDBClustersCommand({
				Filters: [
					{
						Name: "engine",
						Values: ["aurora-mysql", "aurora-postgresql"]
					}
				]
			})
		);

		const clusters = clustersResponse.DBClusters || [];

		if (clusters.length === 0) {
			results.checks.push({
				resourceName: "Aurora Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Aurora clusters found in the region"
			});
			return results;
		}

		// Check each cluster for audit logging configuration
		for (const cluster of clusters) {
			if (!cluster.DBClusterIdentifier) continue;

			// Check if Database Activity Stream is enabled
			const hasActivityStream = cluster.ActivityStreamStatus === "started";

			// A cluster passes if either CloudTrail is configured or Activity Stream is enabled
			const hasAuditLogging = hasValidCloudTrail || hasActivityStream;

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: hasAuditLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasAuditLogging
					? undefined
					: "Neither CloudTrail nor Database Activity Stream is enabled for this Aurora cluster"
			});
		}
	} catch (error) {
		console.log("Error checking Aurora audit logging:", error);
		results.checks.push({
			resourceName: "Aurora Audit Logging Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Aurora audit logging: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAuroraAuditLoggingCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Database Audit Logging is Enabled",
	description:
		"Amazon Aurora provides advanced auditing capabilities through AWS CloudTrail and Amazon RDS Database Activity Streams. At least one of these auditing mechanisms should be enabled for proper monitoring.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_2.6",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkAuroraAuditLoggingCompliance,
	serviceName: "Amazon Relational Database Service"
} satisfies RuntimeTest;
