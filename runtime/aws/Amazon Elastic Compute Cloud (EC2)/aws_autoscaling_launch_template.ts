import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";

import { printSummary, generateSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkAutoScalingLaunchTemplate(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new AutoScalingClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Auto Scaling groups
		const response = await client.send(new DescribeAutoScalingGroupsCommand({}));

		if (!response.AutoScalingGroups || response.AutoScalingGroups.length === 0) {
			results.checks = [
				{
					resourceName: "No Auto Scaling Groups",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Auto Scaling groups found in the region"
				}
			];
			return results;
		}

		// Check each Auto Scaling group
		for (const asg of response.AutoScalingGroups) {
			if (!asg.AutoScalingGroupName) {
				results.checks.push({
					resourceName: "Unknown ASG",
					status: ComplianceStatus.ERROR,
					message: "Auto Scaling group found without name"
				});
				continue;
			}

			// Check if using launch template
			const usesLaunchTemplate = asg.LaunchTemplate !== undefined;
			const usesMixedInstancesTemplate =
				asg.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification !== undefined;

			results.checks.push({
				resourceName: asg.AutoScalingGroupName,
				resourceArn: asg.AutoScalingGroupARN,
				status:
					usesLaunchTemplate || usesMixedInstancesTemplate
						? ComplianceStatus.PASS
						: ComplianceStatus.FAIL,
				message:
					usesLaunchTemplate || usesMixedInstancesTemplate
						? undefined
						: "Auto Scaling group must use launch template instead of launch configuration"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Auto Scaling groups: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkAutoScalingLaunchTemplate(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Amazon EC2 Auto Scaling groups should use Amazon EC2 launch templates",
	description:
		"EC2 Auto Scaling groups must use launch templates instead of launch configurations for better access to latest features.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_AutoScaling.9",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAutoScalingLaunchTemplate
} satisfies RuntimeTest;
