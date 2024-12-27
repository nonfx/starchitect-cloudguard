import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";

import { generateSummary, printSummary } from "../../utils/string-utils";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

const REQUIRED_PATTERN =
	"{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }";

async function checkCmkMonitoringCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
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

		for (const logGroup of logGroups.logGroups) {
			if (!logGroup.logGroupName) continue;

			// Check metric filters for each log group using CloudWatch Logs client
			const metricFilters = await cwLogsClient.send(
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
					message: "Log group does not have required metric filter for CMK monitoring"
				});
				continue;
			}

			// Check if metric filter has associated alarm
			const matchingFilter = metricFilters.metricFilters?.find(
				filter => filter.filterPattern === REQUIRED_PATTERN
			);

			if (matchingFilter?.metricTransformations?.[0]?.metricName) {
				const alarms = await cwClient.send(
					new DescribeAlarmsCommand({
						//@ts-expect-error @todo - to be fixed, temporary fix for CLI unblock
						MetricName: matchingFilter.metricTransformations[0].metricName
					})
				);

				if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
					results.checks.push({
						resourceName: logGroup.logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.FAIL,
						message: "No alarm configured for CMK monitoring metric filter"
					});
				} else {
					results.checks.push({
						resourceName: logGroup.logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.PASS
					});
				}
			}
		}

		if (results.checks.length === 0) {
			results.checks.push({
				resourceName: "CloudWatch Configuration",
				status: ComplianceStatus.FAIL,
				message: "No valid CloudWatch configuration found for CMK monitoring"
			});
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

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkCmkMonitoringCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure disabling or scheduled deletion of customer created CMKs is monitored",
	description:
		"Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for customer created CMKs which have changed state to disabled or scheduled deletion.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_4.7",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCmkMonitoringCompliance
} satisfies RuntimeTest;
