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

import { printSummary, generateSummary } from "../../utils/string-utils.js";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const REQUIRED_PATTERN =
	"{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel) ||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }";

async function checkConfigChangeMonitoring(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
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
					message: "CloudTrail log group does not have required AWS Config changes metric filter"
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
					message: "No alarm configured for AWS Config changes metric filter"
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
			resourceName: "CloudWatch",
			status: ComplianceStatus.ERROR,
			message: `Error checking CloudWatch configuration: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkConfigChangeMonitoring(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure AWS Config configuration changes are monitored",
	description:
		"Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to AWS Config's configurations.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_4.9",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkConfigChangeMonitoring,
	serviceName: "Amazon CloudWatch",
	shortServiceName: "cloudwatch"
} satisfies RuntimeTest;
