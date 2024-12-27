import { CloudWatchClient, GetMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

const REQUIRED_PATTERN =
	'{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }';

async function checkCloudWatchOrgChangesMonitored(
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

			// Check metric filters for each log group
			const metricFilters = await cwLogsClient.send(
				new DescribeMetricFiltersCommand({
					logGroupName: logGroup.logGroupName
				})
			);

			const orgChangeFilter = metricFilters.metricFilters?.find(
				filter => filter.filterPattern === REQUIRED_PATTERN
			);

			if (!orgChangeFilter) {
				results.checks.push({
					resourceName: logGroup.logGroupName,
					resourceArn: logGroup.arn,
					status: ComplianceStatus.FAIL,
					message: "Log group does not have required metric filter for Organizations changes"
				});
				continue;
			}

			// Check if metric has data (indicating active monitoring)
			const metricName = orgChangeFilter.metricTransformations?.[0]?.metricName;
			if (!metricName) {
				results.checks.push({
					resourceName: logGroup.logGroupName,
					resourceArn: logGroup.arn,
					status: ComplianceStatus.FAIL,
					message: "Metric filter does not have a metric transformation"
				});
				continue;
			}

			const endTime = new Date();
			const startTime = new Date();
			startTime.setHours(startTime.getHours() - 24); // Check last 24 hours

			const metricData = await cwClient.send(
				new GetMetricDataCommand({
					MetricDataQueries: [
						{
							Id: "m1",
							MetricStat: {
								Metric: {
									MetricName: metricName,
									Namespace:
										orgChangeFilter.metricTransformations[0].metricNamespace || "CloudTrail"
								},
								Period: 3600,
								Stat: "Sum"
							}
						}
					],
					StartTime: startTime,
					EndTime: endTime
				})
			);

			if (!metricData.MetricDataResults?.[0]?.Values?.length) {
				results.checks.push({
					resourceName: logGroup.logGroupName,
					resourceArn: logGroup.arn,
					status: ComplianceStatus.FAIL,
					message: "No metric data found for Organizations changes monitoring"
				});
				continue;
			}

			results.checks.push({
				resourceName: logGroup.logGroupName,
				resourceArn: logGroup.arn,
				status: ComplianceStatus.PASS,
				message: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "CloudWatch",
			status: ComplianceStatus.ERROR,
			message: `Error checking CloudWatch configuration: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkCloudWatchOrgChangesMonitored(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure AWS Organizations changes are monitored",
	description:
		"Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for AWS Organizations changes made in the master AWS Account.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_4.15",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudWatchOrgChangesMonitored
} satisfies RuntimeTest;
