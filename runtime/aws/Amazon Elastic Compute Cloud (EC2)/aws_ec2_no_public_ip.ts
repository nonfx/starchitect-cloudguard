import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";

import { printSummary, generateSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkEc2PublicIpCompliance(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;

		do {
			const command = new DescribeInstancesCommand({
				NextToken: nextToken
			});

			const response = await client.send(command);

			if (!response.Reservations || response.Reservations.length === 0) {
				if (results.checks.length === 0) {
					results.checks.push({
						resourceName: "No EC2 Instances",
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No EC2 instances found in the region"
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

					// Check for public IP in main network interface
					const hasPublicIp = instance.PublicIpAddress !== undefined;

					// Check for public IP in additional network interfaces
					const hasPublicIpInNetworkInterface = instance.NetworkInterfaces?.some(
						ni => ni.Association?.PublicIp !== undefined
					);

					results.checks.push({
						resourceName: instance.InstanceId,

						//@ts-expect-error @todo - to be fixed, temporary fix for CLI unblock
						resourceArn: `arn:aws:ec2:${region}:${instance.OwnerId}:instance/${instance.InstanceId}`,
						status:
							hasPublicIp || hasPublicIpInNetworkInterface
								? ComplianceStatus.FAIL
								: ComplianceStatus.PASS,
						message:
							hasPublicIp || hasPublicIpInNetworkInterface
								? "EC2 instance has a public IPv4 address configured"
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
	const results = await checkEc2PublicIpCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Amazon EC2 instances should not have a public IPv4 address",
	description:
		"This control checks whether EC2 instances have a public IPv4 address. The control fails if an EC2 instance has a public IP address configured.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.9",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEc2PublicIpCompliance
} satisfies RuntimeTest;
