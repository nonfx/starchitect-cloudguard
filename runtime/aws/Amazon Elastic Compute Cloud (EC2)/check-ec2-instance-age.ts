import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEc2InstanceAge(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let instanceFound = false;

		do {
			const command = new DescribeInstancesCommand({
				NextToken: nextToken,
				Filters: [
					{
						Name: "instance-state-name",
						Values: ["running"]
					}
				]
			});

			const response = await client.send(command);

			if (!response.Reservations || response.Reservations.length === 0) {
				if (!instanceFound) {
					results.checks = [
						{
							resourceName: "No EC2 Instances",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No running EC2 instances found in the region"
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

					if (!instance.InstanceId || !instance.LaunchTime) {
						results.checks.push({
							resourceName: instance.InstanceId || "Unknown Instance",
							status: ComplianceStatus.ERROR,
							message: "Instance missing ID or launch time"
						});
						continue;
					}

					const instanceAge = Math.floor(
						(new Date().getTime() - instance.LaunchTime.getTime()) / (1000 * 60 * 60 * 24)
					);

					results.checks.push({
						resourceName: instance.InstanceId,
						status: instanceAge <= 180 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message:
							instanceAge > 180
								? `Instance is ${instanceAge} days old, exceeding 180 days limit`
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

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkEc2InstanceAge(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure no AWS EC2 Instances are Older than 180 days",
	description: "Identify any running AWS EC2 instances older than 180 days.",
	controls: [
		{
			id: "CUSTOM-AWS-EC2-Instance-Age",
			document: "Custom"
		}
	],
	severity: "MEDIUM",
	execute: checkEc2InstanceAge,
	serviceName: "Amazon Elastic Compute Cloud (EC2)",
	shortServiceName: "ec2"
} satisfies RuntimeTest;
