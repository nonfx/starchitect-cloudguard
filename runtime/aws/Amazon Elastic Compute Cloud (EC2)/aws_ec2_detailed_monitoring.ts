import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEc2DetailedMonitoring(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;

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
				if (results.checks.length === 0) {
					results.checks.push({
						resourceName: "No EC2 Instances",
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No running EC2 instances found in the region"
					});
				}
				break;
			}

			for (const reservation of response.Reservations) {
				if (!reservation.Instances) continue;

				for (const instance of reservation.Instances) {
					if (!instance.InstanceId) {
						results.checks.push({
							resourceName: "Unknown Instance",
							status: ComplianceStatus.ERROR,
							message: "Instance found without ID"
						});
						continue;
					}

					const isDetailedMonitoringEnabled = instance.Monitoring?.State === "enabled";

					results.checks.push({
						resourceName: instance.InstanceId,

						//@ts-expect-error @todo - to be fixed, temporary fix for CLI unblock
						resourceArn: `arn:aws:ec2:${region}:${instance.OwnerId}:instance/${instance.InstanceId}`,
						status: isDetailedMonitoringEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: isDetailedMonitoringEnabled
							? undefined
							: "Detailed monitoring is not enabled for this EC2 instance"
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
	const results = await checkEc2DetailedMonitoring(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure detailed monitoring is enable for production EC2 Instances",
	description: "Ensure that detailed monitoring is enabled for your Amazon EC2 instances.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.6",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEc2DetailedMonitoring
} satisfies RuntimeTest;
