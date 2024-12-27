import { CloudWatchLogsClient, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkCloudWatchLogGroupRetention(
	region: string = "us-east-1",
	minRetentionDays: number = 365
): Promise<ComplianceReport> {
	const client = new CloudWatchLogsClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let logGroupFound = false;

		do {
			const command = new DescribeLogGroupsCommand({
				nextToken
			});

			const response = await client.send(command);

			if (!response.logGroups || response.logGroups.length === 0) {
				if (!logGroupFound) {
					results.checks = [
						{
							resourceName: "No Log Groups",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No CloudWatch log groups found in the region"
						}
					];
					return results;
				}
				break;
			}

			for (const logGroup of response.logGroups) {
				logGroupFound = true;
				const logGroupName = logGroup.logGroupName || "Unknown Log Group";

				if (!logGroup.arn) {
					results.checks.push({
						resourceName: logGroupName,
						status: ComplianceStatus.ERROR,
						message: "Log group missing ARN"
					});
					continue;
				}

				// Check retention period
				const retentionDays = logGroup.retentionInDays;

				if (retentionDays === undefined || retentionDays === null) {
					results.checks.push({
						resourceName: logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.FAIL,
						message: "No retention period configured (logs retained indefinitely)"
					});
				} else if (retentionDays === 0) {
					results.checks.push({
						resourceName: logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.PASS,
						message: "Retention set to never expire"
					});
				} else if (retentionDays < minRetentionDays) {
					results.checks.push({
						resourceName: logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.FAIL,
						message: `Retention period (${retentionDays} days) is less than required (${minRetentionDays} days)`
					});
				} else {
					results.checks.push({
						resourceName: logGroupName,
						resourceArn: logGroup.arn,
						status: ComplianceStatus.PASS
					});
				}
			}

			nextToken = response.nextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "CloudWatch Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking CloudWatch log groups: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkCloudWatchLogGroupRetention(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudWatch log groups should be retained for a specified time period",
	description:
		"This control checks whether an Amazon CloudWatch log group has a retention period of at least the specified number of days. The control fails if the retention period is less than the specified number. Unless you provide a custom parameter value for the retention period, Security Hub uses a default value of 365 days. CloudWatch Logs centralize logs from all of your systems, applications, and AWS services in a single, highly scalable service. You can use CloudWatch Logs to monitor, store, and access your log files from Amazon Elastic Compute Cloud (EC2) instances, AWS CloudTrail, Amazon Route 53, and other sources. Retaining your logs for at least 1 year can help you comply with log retention standards.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudWatch.16",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudWatchLogGroupRetention
} satisfies RuntimeTest;
