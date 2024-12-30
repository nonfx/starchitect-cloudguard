import { CloudWatchClient, DescribeAlarmsForMetricCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";
import {
	CloudTrailClient,
	DescribeTrailsCommand,
	GetTrailStatusCommand
} from "@aws-sdk/client-cloudtrail";

import { generateSummary, printSummary } from "../../utils/string-utils.js";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const REQUIRED_PATTERN =
	"{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }";

async function checkCmkMonitoringCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const cwClient = new CloudWatchClient({ region });
	const cwLogsClient = new CloudWatchLogsClient({ region });
	const cloudTrailClient = new CloudTrailClient({ region });

	const results: ComplianceReport = {
		checks: []
	};

	try {
		const trails = await cloudTrailClient.send(new DescribeTrailsCommand({}));

		if (!trails.trailList || trails.trailList.length === 0) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.FAIL,
				message: "No CloudTrail trails found"
			});
			return results;
		}

		const trailsWithCloudWatchLogs = trails.trailList.filter(
			trail => trail.CloudWatchLogsLogGroupArn
		);

		if (trailsWithCloudWatchLogs.length === 0) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.FAIL,
				message: "No CloudTrail trails found with CloudWatch Logs enabled"
			});
			return results;
		}

		for (const trail of trailsWithCloudWatchLogs) {
			const trailStatus = await cloudTrailClient.send(
				new GetTrailStatusCommand({ Name: trail.TrailARN })
			);

			if (!trailStatus.IsLogging) {
				results.checks.push({
					resourceName: trail.Name || "CloudTrail",
					resourceArn: trail.TrailARN,
					status: ComplianceStatus.FAIL,
					message: "CloudTrail logging is not enabled"
				});
				continue;
			}

			const logGroupArn = trail.CloudWatchLogsLogGroupArn;
			const logGroupParts = logGroupArn?.split(":log-group:");
			const logGroupName = logGroupParts?.[1]?.split(":")[0];

			if (!logGroupName) {
				results.checks.push({
					resourceName: trail.Name || "CloudTrail",
					resourceArn: trail.TrailARN,
					status: ComplianceStatus.FAIL,
					message: "Invalid CloudWatch Logs configuration"
				});
				continue;
			}

			const metricFilters = await cwLogsClient.send(
				new DescribeMetricFiltersCommand({
					logGroupName: logGroupName
				})
			);

			const matchingFilter = metricFilters.metricFilters?.find(
				filter => filter.filterPattern && filter.filterPattern === REQUIRED_PATTERN
			);

			if (!matchingFilter) {
				results.checks.push({
					resourceName: logGroupName,
					resourceArn: logGroupArn,
					status: ComplianceStatus.FAIL,
					message: "CloudTrail log group does not have required CMK monitoring metric filter"
				});
				continue;
			}

			const metricTransformation = matchingFilter.metricTransformations?.[0];
			if (!metricTransformation?.metricName) {
				results.checks.push({
					resourceName: logGroupName,
					resourceArn: logGroupArn,
					status: ComplianceStatus.FAIL,
					message: "Metric filter does not have a valid metric transformation"
				});
				continue;
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
					message: "No alarm configured for CMK monitoring metric filter"
				});
			} else {
				results.checks.push({
					resourceName: logGroupName,
					resourceArn: logGroupArn,
					status: ComplianceStatus.PASS,
					message: undefined
				});
				break;
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
	execute: checkCmkMonitoringCompliance,
	serviceName: "Amazon CloudWatch",
	shortServiceName: "cloudwatch"
} satisfies RuntimeTest;
