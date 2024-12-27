import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

const REQUIRED_PATTERN =
	'{ ($.userIdentity.type = "Root") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != "AwsServiceEvent") }';

async function checkRootAccountMonitoring(region: string = "us-east-1"): Promise<ComplianceReport> {
	const cwClient = new CloudWatchClient({ region });
	const cwLogsClient = new CloudWatchLogsClient({ region });

	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all log groups
		const logGroups = await cwLogsClient.send(new DescribeLogGroupsCommand({}));

		if (!logGroups.logGroups || logGroups.logGroups.length === 0) {
			results.checks.push({
				resourceName: "CloudWatch Logs",
				status: ComplianceStatus.FAIL,
				message: "No CloudWatch Log Groups found"
			});
			return results;
		}

		// Check each log group for metric filters
		for (const logGroup of logGroups.logGroups) {
			if (!logGroup.logGroupName) continue;

			try {
				const metricFilters = await cwLogsClient.send(
					new DescribeMetricFiltersCommand({
						logGroupName: logGroup.logGroupName
					})
				);

				const rootActivityFilter = metricFilters.metricFilters?.find(
					filter => filter.filterPattern === REQUIRED_PATTERN
				);

				if (!rootActivityFilter) {
					results.checks.push({
						resourceName: logGroup.logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.FAIL,
						message: "Log group does not have required metric filter for root account activity"
					});
					continue;
				}

				// Check for alarms associated with the metric filter
				const metricName = rootActivityFilter.metricTransformations?.[0]?.metricName;
				if (!metricName) {
					results.checks.push({
						resourceName: logGroup.logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.FAIL,
						message: "Metric filter does not have a metric transformation"
					});
					continue;
				}

				const alarms = await cwClient.send(
					new DescribeAlarmsCommand({
						MetricName: metricName
					})
				);

				if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
					results.checks.push({
						resourceName: logGroup.logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.FAIL,
						message: "No alarms configured for root account activity metric"
					});
					continue;
				}

				results.checks.push({
					resourceName: logGroup.logGroupName,
					resourceArn: logGroup.arn,
					status: ComplianceStatus.PASS,
					message: undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: logGroup.logGroupName,
					resourceArn: logGroup.arn,
					status: ComplianceStatus.ERROR,
					message: `Error checking metric filters: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "CloudWatch",
			status: ComplianceStatus.ERROR,
			message: `Error checking root account monitoring: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkRootAccountMonitoring(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure usage of 'root' account is monitored",
	description:
		"The use of the root account should be avoided as much as possible. When the root account is used, it's critical to monitor this activity in real-time by directing CloudTrail Logs to CloudWatch Logs, or an external SIEM environment, and establishing corresponding metric filters and alarms.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_4.3",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		},
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudWatch.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkRootAccountMonitoring
} satisfies RuntimeTest;
