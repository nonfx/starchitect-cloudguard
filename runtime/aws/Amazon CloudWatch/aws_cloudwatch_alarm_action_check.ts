import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudWatchAlarmActions(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new CloudWatchClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let alarmsFound = false;

		do {
			const command = new DescribeAlarmsCommand({
				NextToken: nextToken
			});

			const response = await client.send(command);

			if (!response.MetricAlarms || response.MetricAlarms.length === 0) {
				if (!alarmsFound) {
					results.checks = [
						{
							resourceName: "No CloudWatch Alarms",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No CloudWatch alarms found in the region"
						}
					];
					return results;
				}
				break;
			}

			alarmsFound = true;

			for (const alarm of response.MetricAlarms) {
				if (!alarm.AlarmName) {
					results.checks.push({
						resourceName: "Unknown Alarm",
						status: ComplianceStatus.ERROR,
						message: "Alarm found without name"
					});
					continue;
				}

				const hasAlarmActions = alarm.AlarmActions && alarm.AlarmActions.length > 0;

				results.checks.push({
					resourceName: alarm.AlarmName,
					resourceArn: alarm.AlarmArn,
					status: hasAlarmActions ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasAlarmActions
						? undefined
						: "CloudWatch alarm does not have any actions configured for ALARM state"
				});
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "CloudWatch Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking CloudWatch alarms: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkCloudWatchAlarmActions(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudWatch alarms should have specified actions configured",
	description:
		"This control checks whether an Amazon CloudWatch alarm has at least one action configured for the ALARM state. The control fails if the alarm doesn't have an action configured for the ALARM state. Optionally, you can include custom parameter values to also require alarm actions for the INSUFFICIENT_DATA or OK states. This control focuses on whether a CloudWatch alarm has an alarm action configured, whereas CloudWatch.17 focuses on the activation status of a CloudWatch alarm action. We recommend CloudWatch alarm actions to automatically alert you when a monitored metric is outside the defined threshold.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.15",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudWatchAlarmActions,
	serviceName: "Amazon CloudWatch",
	shortServiceName: "cloudwatch"
} satisfies RuntimeTest;
