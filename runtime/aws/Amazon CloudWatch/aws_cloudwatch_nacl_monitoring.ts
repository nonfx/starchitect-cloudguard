import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";

import {
	CloudWatchLogsClient,
	DescribeLogGroupsCommand,
	DescribeMetricFiltersCommand
} from "@aws-sdk/client-cloudwatch-logs";

import { generateSummary, printSummary } from "../../utils/string-utils";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

const REQUIRED_PATTERN =
	"{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }";

async function checkNaclMonitoringCompliance(
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

		// Check each log group for required metric filters
		for (const logGroup of logGroups.logGroups) {
			if (!logGroup.logGroupName) continue;

			const metricFilters = await cwLogsClient.send(
				new DescribeMetricFiltersCommand({
					logGroupName: logGroup.logGroupName
				})
			);

			const naclFilter = metricFilters.metricFilters?.find(
				filter => filter.filterPattern === REQUIRED_PATTERN
			);

			if (!naclFilter) {
				results.checks.push({
					resourceName: logGroup.logGroupName,
					resourceArn: logGroup.arn,
					status: ComplianceStatus.FAIL,
					message: "Log group does not have required NACL changes metric filter"
				});
				continue;
			}

			// Check for alarms associated with the metric filter
			const metricName = naclFilter.metricTransformations?.[0]?.metricName;
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
					//@ts-expect-error @todo - to be fixed, temporary fix for CLI unblock
					MetricName: metricName
				})
			);

			if (!alarms.MetricAlarms || alarms.MetricAlarms.length === 0) {
				results.checks.push({
					resourceName: logGroup.logGroupName,
					resourceArn: logGroup.arn,
					status: ComplianceStatus.FAIL,
					message: "No alarms configured for NACL changes metric"
				});
			} else {
				results.checks.push({
					resourceName: logGroup.logGroupName,
					resourceArn: logGroup.arn,
					status: ComplianceStatus.PASS
				});
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
	const results = await checkNaclMonitoringCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Network Access Control Lists (NACL) changes are monitored",
	description:
		"Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. NACLs are used as a stateless packet filter to control ingress and egress traffic for subnets within a VPC. It is recommended that a metric filter and alarm be established for changes made to NACLs",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_4.11",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkNaclMonitoringCompliance
} satisfies RuntimeTest;
