import { CloudWatchClient, DescribeAlarmsForMetricCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import {
	CloudTrailClient,
	DescribeTrailsCommand,
	GetTrailStatusCommand
} from "@aws-sdk/client-cloudtrail";

import { printSummary, generateSummary } from "../../utils/string-utils.js";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const REQUIRED_PATTERN =
	'{ ($.userIdentity.type = "Root") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != "AwsServiceEvent") }';

async function checkRootAccountMonitoring(region: string = "us-east-1"): Promise<ComplianceReport> {
	const cwClient = new CloudWatchClient({ region });
	const cwLogsClient = new CloudWatchLogsClient({ region });
	const cloudTrailClient = new CloudTrailClient({ region });

	const results: ComplianceReport = {
		checks: []
	};

	try {
		// First check if CloudTrail exists and is enabled
		const trails = await cloudTrailClient.send(new DescribeTrailsCommand({}));

		if (!trails.trailList || trails.trailList.length === 0) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.FAIL,
				message: "No CloudTrail trails found"
			});
			return results;
		}

		// Find a trail that has CloudWatch Logs enabled
		const trailWithCloudWatchLogs = trails.trailList.find(trail => trail.CloudWatchLogsLogGroupArn);

		if (!trailWithCloudWatchLogs) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.FAIL,
				message: "No CloudTrail trails found with CloudWatch Logs enabled"
			});
			return results;
		}

		// Check if the trail is enabled
		const trailStatus = await cloudTrailClient.send(
			new GetTrailStatusCommand({ Name: trailWithCloudWatchLogs.TrailARN })
		);

		if (!trailStatus.IsLogging) {
			results.checks.push({
				resourceName: trailWithCloudWatchLogs.Name || "CloudTrail",
				resourceArn: trailWithCloudWatchLogs.TrailARN,
				status: ComplianceStatus.FAIL,
				message: "CloudTrail logging is not enabled"
			});
			return results;
		}

		// Extract log group name from ARN (e.g. "arn:aws:logs:ap-southeast-1:891377036258:log-group:test:*")
		const logGroupArn = trailWithCloudWatchLogs.CloudWatchLogsLogGroupArn;
		const logGroupParts = logGroupArn?.split(":log-group:");
		const logGroupName = logGroupParts?.[1]?.split(":")[0];

		if (!logGroupName) {
			results.checks.push({
				resourceName: trailWithCloudWatchLogs.Name || "CloudTrail",
				resourceArn: trailWithCloudWatchLogs.TrailARN,
				status: ComplianceStatus.FAIL,
				message: "Invalid CloudWatch Logs configuration"
			});
			return results;
		}

		// Check for metric filter in the CloudTrail log group
		const metricFilters = await cwLogsClient.send(
			new DescribeMetricFiltersCommand({
				logGroupName: logGroupName
			})
		);

		const matchingFilter = metricFilters.metricFilters?.find(
			filter =>
				filter.filterPattern &&
				filter.filterPattern.replace(/\s+/g, " ").trim() ===
					REQUIRED_PATTERN.replace(/\s+/g, " ").trim()
		);

		if (!matchingFilter) {
			results.checks.push({
				resourceName: logGroupName,
				resourceArn: logGroupArn,
				status: ComplianceStatus.FAIL,
				message: "CloudTrail log group does not have required root account activity metric filter"
			});
			return results;
		}

		const metricTransformation = matchingFilter.metricTransformations?.[0];
		if (!metricTransformation?.metricName) {
			results.checks.push({
				resourceName: logGroupName,
				resourceArn: logGroupArn,
				status: ComplianceStatus.FAIL,
				message: "Metric filter does not have a valid metric transformation"
			});
			return results;
		}

		const alarms = await cwClient.send(
			new DescribeAlarmsForMetricCommand({
				MetricName: metricTransformation.metricName,
				Namespace: metricTransformation.metricNamespace || "CloudWatchLogs"
			})
		);

		if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
			results.checks.push({
				resourceName: logGroupName,
				resourceArn: logGroupArn,
				status: ComplianceStatus.FAIL,
				message: "No alarms configured for root account activity metric"
			});
		} else {
			results.checks.push({
				resourceName: logGroupName,
				resourceArn: logGroupArn,
				status: ComplianceStatus.PASS,
				message: undefined
			});
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
