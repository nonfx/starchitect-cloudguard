import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";

import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

const REQUIRED_PATTERN =
	"{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }";

async function checkCloudTrailConfigurationMonitoring(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const logsClient = new CloudWatchLogsClient({ region });
	const cloudWatchClient = new CloudWatchClient({ region });

	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all log groups
		const logGroups = await logsClient.send(new DescribeLogGroupsCommand({}));

		if (!logGroups.logGroups || logGroups.logGroups.length === 0) {
			results.checks.push({
				resourceName: "CloudWatch Logs",
				status: ComplianceStatus.FAIL,
				message: "No CloudWatch Log Groups found"
			});
			return results;
		}

		for (const logGroup of logGroups.logGroups) {
			if (!logGroup.logGroupName) continue;

			// Check metric filters for each log group
			const metricFilters = await logsClient.send(
				new DescribeMetricFiltersCommand({
					logGroupName: logGroup.logGroupName
				})
			);

			const hasRequiredFilter = metricFilters.metricFilters?.some(
				filter => filter.filterPattern === REQUIRED_PATTERN
			);

			if (!hasRequiredFilter) {
				results.checks.push({
					resourceName: logGroup.logGroupName,
					resourceArn: logGroup.arn,
					status: ComplianceStatus.FAIL,
					message:
						"Log group does not have required metric filter for CloudTrail configuration changes"
				});
				continue;
			}

			// Check if metric filter has associated alarm
			const matchingFilter = metricFilters.metricFilters?.find(
				filter => filter.filterPattern === REQUIRED_PATTERN
			);

			if (matchingFilter?.metricTransformations?.[0]?.metricName) {
				const alarms = await cloudWatchClient.send(
					new DescribeAlarmsCommand({
						MetricName: matchingFilter.metricTransformations[0].metricName
					})
				);

				if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
					results.checks.push({
						resourceName: logGroup.logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.FAIL,
						message: "No alarm configured for CloudTrail configuration changes metric filter"
					});
				} else {
					results.checks.push({
						resourceName: logGroup.logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.PASS,
						message: undefined
					});
				}
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "CloudWatch Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking CloudWatch configuration: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkCloudTrailConfigurationMonitoring(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure CloudTrail configuration changes are monitored",
	description:
		"Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, where metric filters and alarms can be established. It is recommended that a metric filter and alarm be utilized for detecting changes to CloudTrail's configurations.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_4.5",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		},
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudTrailConfigurationMonitoring
} satisfies RuntimeTest;
