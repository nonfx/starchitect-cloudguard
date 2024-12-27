import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";

import { printSummary, generateSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkCloudWatchAlarmActionsEnabled(
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

			for (const alarm of response.MetricAlarms) {
				alarmsFound = true;
				const alarmName = alarm.AlarmName || "Unknown Alarm";
				const alarmArn = alarm.AlarmArn;

				results.checks.push({
					resourceName: alarmName,
					resourceArn: alarmArn,
					status: alarm.ActionsEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: alarm.ActionsEnabled ? undefined : "CloudWatch alarm actions are not activated"
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
	const results = await checkCloudWatchAlarmActionsEnabled(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudWatch alarm actions should be activated",
	description:
		"This control checks whether CloudWatch alarm actions are activated (ActionEnabled should be set to true). The control fails if the alarm action for a CloudWatch alarm is deactivated. This control focuses on the activation status of a CloudWatch alarm action, whereas CloudWatch.15 focuses on whether any ALARM action is configured in a CloudWatch alarm. Alarm actions automatically alert you when a monitored metric is outside the defined threshold. If the alarm action is deactivated, no actions are run when the alarm changes state, and you won't be alerted to changes in monitored metrics. We recommend activating CloudWatch alarm actions to help you quickly respond to security and operational issues.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudWatch.17",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudWatchAlarmActionsEnabled
} satisfies RuntimeTest;
