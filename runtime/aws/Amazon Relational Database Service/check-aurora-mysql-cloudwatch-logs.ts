import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkAuroraMysqlCloudWatchLogs(
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
					resourceName: "No DB Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Aurora MySQL DB clusters found in the region"
				}
			];
			return results;
		}

		// Check each cluster
		for (const cluster of response.DBClusters) {
			// Skip if not Aurora MySQL
			if (!cluster.Engine?.startsWith("aurora-mysql")) {
				continue;
			}

			const clusterName = cluster.DBClusterIdentifier || "Unknown Cluster";

			// Check if audit logs are enabled
			const hasAuditLogs = cluster.EnabledCloudwatchLogsExports?.includes("audit");

			results.checks.push({
				resourceName: clusterName,
				resourceArn: cluster.DBClusterArn,
				status: hasAuditLogs ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasAuditLogs
					? undefined
					: "Aurora MySQL cluster does not have audit logs enabled in CloudWatch Logs exports"
			});
		}

		// If no Aurora MySQL clusters were found
		if (results.checks.length === 0) {
			results.checks.push({
				resourceName: "No Aurora MySQL Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Aurora MySQL DB clusters found in the region"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Aurora MySQL clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkAuroraMysqlCloudWatchLogs(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Aurora MySQL DB clusters should publish audit logs to CloudWatch Logs",
	description:
		"Ensures that Aurora MySQL DB clusters are configured to publish audit logs to CloudWatch Logs for monitoring and compliance purposes.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.34",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkAuroraMysqlCloudWatchLogs
} satisfies RuntimeTest;
