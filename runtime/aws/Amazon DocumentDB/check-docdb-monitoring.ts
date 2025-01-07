import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocDBMonitoringCompliance(
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

			const hasMonitoring =
				cluster.EnabledCloudwatchLogsExports && cluster.EnabledCloudwatchLogsExports.length > 0;

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: hasMonitoring ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasMonitoring ? undefined : "Monitoring is not enabled for this DocumentDB cluster"
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
	const results = await checkDocDBMonitoringCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure to Implement Monitoring and Alerting - Monitoring",
	description:
		"This helps by alerting the system if any unusual event has occurred or if a particular threshold has been achieved because the user is able to set a desired interval or the cluster. This then allows system administrators to swiftly correct the situation and avoid subsequent complications if something unusual is happening.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.8_a",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDocDBMonitoringCompliance,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
