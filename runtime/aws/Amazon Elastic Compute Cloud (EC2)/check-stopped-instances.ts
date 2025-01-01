import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

function parseStopTime(stateTransitionReason: string): Date | null {
	const stopTimeMatch = stateTransitionReason.match(/\((.*?)\)/);
	if (!stopTimeMatch || !stopTimeMatch[1]) return null;

	const parsedDate = new Date(stopTimeMatch[1]);
	return isNaN(parsedDate.getTime()) ? null : parsedDate;
}

async function checkStoppedInstances(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let instanceFound = false;

		do {
			const command = new DescribeInstancesCommand({
				Filters: [
					{
						Name: "instance-state-name",
						Values: ["stopped"]
					}
				],
				NextToken: nextToken
			});

			const response = await client.send(command);

			if (!response.Reservations?.length) {
				if (!instanceFound) {
					results.checks = [
						{
							resourceName: "No EC2 Instances",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No stopped EC2 instances found in the region"
						}
					];
					return results;
				}
				break;
			}

			for (const reservation of response.Reservations) {
				if (!reservation.Instances) continue;

				for (const instance of reservation.Instances) {
					instanceFound = true;
					const instanceId = instance.InstanceId || "Unknown Instance";

					if (!instance.StateTransitionReason) {
						results.checks.push({
							resourceName: instanceId,
							status: ComplianceStatus.ERROR,
							message: "Instance missing state transition information"
						});
						continue;
					}

					const stopTime = parseStopTime(instance.StateTransitionReason);
					if (!stopTime) {
						results.checks.push({
							resourceName: instanceId,
							status: ComplianceStatus.ERROR,
							message: "Unable to determine instance stop time"
						});
						continue;
					}

					const currentTime = new Date().getTime();
					const stoppedDuration = currentTime - stopTime.getTime();
					const stoppedDays = Math.floor(stoppedDuration / (24 * 60 * 60 * 1000));

					results.checks.push({
						resourceName: instanceId,
						resourceArn:
							instanceId !== "Unknown Instance"
								? `arn:aws:ec2:${region}:${process.env.AWS_ACCOUNT_ID || ""}:instance/${instanceId}`
								: undefined,
						status:
							stoppedDuration > NINETY_DAYS_MS ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
						message:
							stoppedDuration > NINETY_DAYS_MS
								? `Instance has been stopped for ${stoppedDays} days (maximum allowed: 90 days)`
								: undefined
					});
				}
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "EC2 Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking EC2 instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkStoppedInstances(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure instances stopped for over 90 days are removed",
	description:
		"Enable this rule to help with the baseline configuration of Amazon Elastic Compute Cloud (Amazon EC2) instances by checking whether Amazon EC2 instances have been stopped for more than the allowed number of days, according to your organization's standards",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.8",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkStoppedInstances,
	serviceName: "Amazon Elastic Compute Cloud (EC2)",
	shortServiceName: "ec2"
} satisfies RuntimeTest;
