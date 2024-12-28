import {
	AutoScalingClient,
	DescribeLaunchConfigurationsCommand,
	type DescribeLaunchConfigurationsCommandOutput
} from "@aws-sdk/client-auto-scaling";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAutoScalingPublicIp(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new AutoScalingClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let configFound = false;

		do {
			const command = new DescribeLaunchConfigurationsCommand({
				NextToken: nextToken
			});

			const response: DescribeLaunchConfigurationsCommandOutput = await client.send(command);

			if (!response.LaunchConfigurations || response.LaunchConfigurations.length === 0) {
				if (!configFound) {
					results.checks = [
						{
							resourceName: "No Launch Configurations",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No Auto Scaling launch configurations found"
						}
					];
					return results;
				}
				break;
			}

			configFound = true;

			for (const config of response.LaunchConfigurations) {
				if (!config.LaunchConfigurationName) {
					results.checks.push({
						resourceName: "Unknown Configuration",
						status: ComplianceStatus.ERROR,
						message: "Launch configuration found without name"
					});
					continue;
				}

				results.checks.push({
					resourceName: config.LaunchConfigurationName,
					resourceArn: config.LaunchConfigurationARN,
					status: config.AssociatePublicIpAddress ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: config.AssociatePublicIpAddress
						? "Launch configuration assigns public IP addresses to instances"
						: undefined
				});
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "Auto Scaling Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking launch configurations: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkAutoScalingPublicIp(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Auto Scaling group launch configurations should not have Public IP addresses",
	description:
		"Auto Scaling group launch configurations must disable public IP addresses for EC2 instances to enhance network security.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_AutoScaling.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAutoScalingPublicIp
} satisfies RuntimeTest;
