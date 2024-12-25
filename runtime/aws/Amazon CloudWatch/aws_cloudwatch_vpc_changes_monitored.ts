import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

const REQUIRED_PATTERN =
	"{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }";

async function checkVpcChangesMonitored(region: string = "us-east-1"): Promise<ComplianceReport> {
	const cwClient = new CloudWatchClient({ region });
	const cwLogsClient = new CloudWatchLogsClient({ region });

	const results: ComplianceReport = {
		checks: []
	};

	try {
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

			const metricFilters = await cwLogsClient.send(
				new DescribeMetricFiltersCommand({
					logGroupName: logGroup.logGroupName
				})
			);

			const matchingFilter = metricFilters.metricFilters?.find(
				filter => filter.filterPattern === REQUIRED_PATTERN
			);

			if (!matchingFilter) {
				results.checks.push({
					resourceName: logGroup.logGroupName,
					resourceArn: logGroup.arn,
					status: ComplianceStatus.FAIL,
					message: "Log group does not have required VPC changes metric filter"
				});
				continue;
			}

			if (matchingFilter.metricTransformations?.[0]?.metricName) {
				const alarms = await cwClient.send(
					new DescribeAlarmsCommand({
						AlarmNames: [],
						MetricName: matchingFilter.metricTransformations[0].metricName
					})
				);

				if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
					results.checks.push({
						resourceName: logGroup.logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.FAIL,
						message: "No alarm configured for VPC changes metric filter"
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

		if (results.checks.length === 0) {
			results.checks.push({
				resourceName: "CloudWatch Configuration",
				status: ComplianceStatus.FAIL,
				message: "No monitoring configuration found for VPC changes"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "CloudWatch",
			status: ComplianceStatus.ERROR,
			message: `Error checking VPC monitoring: ${
				error instanceof Error ? error.message : String(error)
			}`
		});
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkVpcChangesMonitored(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure VPC changes are monitored",
	description:
		"Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is possible to have more than 1 VPC within an account, in addition it is also possible to create a peer connection between 2 VPCs enabling network traffic to route between VPCs. It is recommended that a metric filter and alarm be established for changes made to VPCs.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_4.14",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkVpcChangesMonitored
} satisfies RuntimeTest;
