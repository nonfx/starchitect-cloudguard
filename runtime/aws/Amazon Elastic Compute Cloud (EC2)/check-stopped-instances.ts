import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

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

			if (!response.Reservations || response.Reservations.length === 0) {
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
					if (!instance.InstanceId || !instance.StateTransitionReason) {
						results.checks.push({
							resourceName: instance.InstanceId || "Unknown Instance",
							status: ComplianceStatus.ERROR,
							message: "Instance missing required information"
						});
						continue;
					}

					// Extract stop time from StateTransitionReason
					const stopTimeMatch = instance.StateTransitionReason.match(/\((.*?)\)/);
					if (!stopTimeMatch) {
						results.checks.push({
							resourceName: instance.InstanceId,
							status: ComplianceStatus.ERROR,
							message: "Unable to determine instance stop time"
						});
						continue;
					}

					const stopTime = new Date(stopTimeMatch[1]).getTime();
					const currentTime = new Date().getTime();
					const stoppedDuration = currentTime - stopTime;

					results.checks.push({
						resourceName: instance.InstanceId,
						status:
							stoppedDuration > NINETY_DAYS_MS ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
						message:
							stoppedDuration > NINETY_DAYS_MS
								? `Instance has been stopped for more than 90 days (${Math.floor(stoppedDuration / (24 * 60 * 60 * 1000))} days)`
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
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
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
	execute: checkStoppedInstances
} satisfies RuntimeTest;
