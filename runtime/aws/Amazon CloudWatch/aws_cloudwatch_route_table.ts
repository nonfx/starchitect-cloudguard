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
	"{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }";

async function checkRouteTableMonitoring(region: string = "us-east-1"): Promise<ComplianceReport> {
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

		const trailWithCloudWatchLogs = trails.trailList.find(trail => trail.CloudWatchLogsLogGroupArn);

		if (!trailWithCloudWatchLogs) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.FAIL,
				message: "No CloudTrail trails found with CloudWatch Logs enabled"
			});
			return results;
		}

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
				message: "CloudTrail log group does not have required route table monitoring metric filter"
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
				message: "No alarms configured for route table monitoring metric"
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
			message: `Error checking route table monitoring: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkRouteTableMonitoring(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure route table changes are monitored",
	description:
		"Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. Routing tables are used to route network traffic between subnets and to network gateways. It is recommended that a metric filter and alarm be established for changes to route tables.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_4.13",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkRouteTableMonitoring
} satisfies RuntimeTest;
