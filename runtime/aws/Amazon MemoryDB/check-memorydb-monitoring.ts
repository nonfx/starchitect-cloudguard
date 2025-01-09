import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkMemoryDBMonitoring(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new CloudWatchClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new DescribeAlarmsCommand({});
		const response = await client.send(command);

		if (!response.MetricAlarms || response.MetricAlarms.length === 0) {
			results.checks = [
				{
					resourceName: "MemoryDB CloudWatch Alarms",
					status: ComplianceStatus.FAIL,
					message: "No CloudWatch alarms found for MemoryDB monitoring"
				}
			];
			return results;
		}

		// Essential metrics that should be monitored
		const essentialMetrics = [
			"CPUUtilization",
			"DatabaseMemoryUsagePercentage",
			"SwapUsage",
			"NetworkBytesIn",
			"NetworkBytesOut",
			"CurrConnections"
		];

		const memoryDBAlarms = response.MetricAlarms.filter(
			alarm => alarm.Namespace === "AWS/MemoryDB"
		);

		const monitoredMetrics = new Set(memoryDBAlarms.map(alarm => alarm.MetricName));
		const unmonitoredMetrics = essentialMetrics.filter(metric => !monitoredMetrics.has(metric));

		// Check for missing essential metrics
		if (unmonitoredMetrics.length > 0) {
			results.checks.push({
				resourceName: "MemoryDB Essential Metrics",
				status: ComplianceStatus.FAIL,
				message: `Missing CloudWatch alarms for essential metrics: ${unmonitoredMetrics.join(", ")}`
			});
		}

		// Check individual alarm configurations
		for (const alarm of response.MetricAlarms) {
			if (!alarm.AlarmName) continue;

			const alarmIssues: string[] = [];

			if (alarm.ActionsEnabled === false) {
				alarmIssues.push("Actions are disabled");
			}

			if (!alarm.AlarmActions || alarm.AlarmActions.length === 0) {
				alarmIssues.push("No alarm actions configured");
			}

			if (alarm.EvaluationPeriods && alarm.EvaluationPeriods < 3) {
				alarmIssues.push(`Low evaluation period (${alarm.EvaluationPeriods})`);
			}

			results.checks.push({
				resourceName: alarm.AlarmName,
				resourceArn: alarm.AlarmArn,
				status: alarmIssues.length > 0 ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message:
					alarmIssues.length > 0
						? `Alarm configuration issues: ${alarmIssues.join(", ")}`
						: undefined
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
