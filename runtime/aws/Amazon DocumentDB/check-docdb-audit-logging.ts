import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocDBClusterAuditLogging(
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

			const hasAuditLogging = cluster.EnabledCloudwatchLogsExports?.includes("audit");

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: hasAuditLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasAuditLogging
					? undefined
					: "DocumentDB cluster does not have audit logging enabled to CloudWatch Logs"
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
	const results = await checkDocDBClusterAuditLogging(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Amazon DocumentDB clusters should publish audit logs to CloudWatch Logs",
	description:
		"Amazon DocumentDB clusters must enable audit logging to CloudWatch Logs for security monitoring and compliance tracking.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_DocumentDB.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		},
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.6",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDocDBClusterAuditLogging,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
