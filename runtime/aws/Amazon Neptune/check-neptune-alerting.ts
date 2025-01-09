import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkNeptuneAlertingCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const neptuneClient = new NeptuneClient({ region });
	const cloudwatchClient = new CloudWatchClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Neptune clusters
		const clusters = await neptuneClient.send(new DescribeDBClustersCommand({}));

		if (!clusters.DBClusters || clusters.DBClusters.length === 0) {
			results.checks = [
				{
					resourceName: "No Neptune Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Neptune clusters found in the region"
				}
			];
			return results;
		}

		// Get all CloudWatch alarms
		const alarms = await cloudwatchClient.send(new DescribeAlarmsCommand({}));

		for (const cluster of clusters.DBClusters) {
			if (!cluster.DBClusterIdentifier) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Neptune cluster found without identifier"
				});
				continue;
			}

			// Check if any alarm exists for this cluster
			const hasAlarms = alarms.MetricAlarms?.some(
				alarm =>
					alarm.Namespace === "AWS/Neptune" &&
					alarm.Dimensions?.some(
						dim => dim.Name === "DBClusterIdentifier" && dim.Value === cluster.DBClusterIdentifier
					)
			);

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: hasAlarms ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasAlarms
					? undefined
					: "Neptune cluster does not have any associated CloudWatch alarms for alerting"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Neptune clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkNeptuneAlertingCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon Neptune",
	shortServiceName: "neptune",
	title: "Ensure Monitoring and Alerting is Enabled - Alerting",
	description: "",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_9.7",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkNeptuneAlertingCompliance
} satisfies RuntimeTest;
