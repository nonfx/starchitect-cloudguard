import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkAuroraPostgresCloudWatchLogs(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DB clusters
		const response = await client.send(new DescribeDBClustersCommand({}));

		if (!response.DBClusters || response.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No DB Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Aurora PostgreSQL DB clusters found in the region"
				}
			];
			return results;
		}

		// Filter and check Aurora PostgreSQL clusters
		const postgresqlClusters = response.DBClusters.filter(cluster =>
			cluster.Engine?.startsWith("aurora-postgresql")
		);

		if (postgresqlClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No PostgreSQL Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Aurora PostgreSQL DB clusters found in the region"
				}
			];
			return results;
		}

		// Check each PostgreSQL cluster
		for (const cluster of postgresqlClusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			const hasPostgresLogs = cluster.EnabledCloudwatchLogsExports?.includes("postgresql");

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: hasPostgresLogs ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasPostgresLogs
					? undefined
					: "Aurora PostgreSQL cluster is not configured to publish PostgreSQL logs to CloudWatch Logs"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Aurora PostgreSQL clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkAuroraPostgresCloudWatchLogs(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Aurora PostgreSQL DB clusters should publish logs to CloudWatch Logs",
	description:
		"This control checks whether Aurora PostgreSQL DB clusters are configured to publish logs to Amazon CloudWatch Logs.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.37",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkAuroraPostgresCloudWatchLogs
} satisfies RuntimeTest;
