import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { MemoryDBClient } from "@aws-sdk/client-memorydb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllMemoryDBClusters } from "../../utils/aws/get-all-memorydb-clusters.js";

async function checkMemoryDBMonitoring(region: string = "us-east-1"): Promise<ComplianceReport> {
	const cloudwatchClient = new CloudWatchClient({ region });
	const memorydbClient = new MemoryDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all MemoryDB clusters
		const clusters = await getAllMemoryDBClusters(memorydbClient);
		if (clusters.length === 0) {
			results.checks = [
				{
					resourceName: "MemoryDB Clusters",
					status: ComplianceStatus.PASS,
					message: "No MemoryDB clusters found in the region"
				}
			];
			return results;
		}

		// Get all CloudWatch alarms
		const command = new DescribeAlarmsCommand({});
		const response = await cloudwatchClient.send(command);

		// Essential metrics that should be monitored
		const essentialMetrics = [
			"CPUUtilization",
			"DatabaseMemoryUsagePercentage",
			"SwapUsage",
			"NetworkBytesIn",
			"NetworkBytesOut",
			"CurrConnections"
		];

		// Check monitoring for each cluster
		for (const cluster of clusters) {
			if (!cluster.Name) continue;

			const clusterAlarms =
				response.MetricAlarms?.filter(
					alarm =>
						alarm.Namespace === "AWS/MemoryDB" &&
						alarm.Dimensions?.some(d => d.Name === "ClusterName" && d.Value === cluster.Name)
				) || [];

			const issues: string[] = [];

			// Check for missing essential metrics
			const monitoredMetrics = new Set(clusterAlarms.map(alarm => alarm.MetricName));
			const unmonitoredMetrics = essentialMetrics.filter(metric => !monitoredMetrics.has(metric));

			if (unmonitoredMetrics.length > 0) {
				issues.push(`Missing metrics: ${unmonitoredMetrics.join(", ")}`);
			}

			// Check alarm configurations
			const configurationIssues = clusterAlarms.filter(alarm => {
				const alarmIssues = [];
				if (alarm.ActionsEnabled === false) alarmIssues.push("Actions disabled");
				if (!alarm.AlarmActions?.length) alarmIssues.push("No actions configured");
				if ((alarm.EvaluationPeriods || 0) < 3) alarmIssues.push("Low evaluation period");
				return alarmIssues.length > 0;
			});

			if (configurationIssues.length > 0) {
				issues.push("Some alarms have configuration issues");
			}

			results.checks.push({
				resourceName: cluster.Name,
				resourceArn: cluster.ARN,
				status: issues.length > 0 ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: issues.length > 0 ? issues.join("; ") : undefined
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "MemoryDB Monitoring Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking MemoryDB monitoring: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkMemoryDBMonitoring(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon MemoryDB",
	shortServiceName: "memorydb",
	title: "Ensure MemoryDB Clusters are Properly Monitored",
	description:
		"Checks if MemoryDB clusters have proper CloudWatch monitoring configured with essential metrics and properly configured alarms.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_6.7",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkMemoryDBMonitoring
} satisfies RuntimeTest;
