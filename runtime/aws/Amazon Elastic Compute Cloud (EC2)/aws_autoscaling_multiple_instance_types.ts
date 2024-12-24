import {
	AutoScalingClient,
	DescribeAutoScalingGroupsCommand,
	type AutoScalingGroup
} from "@aws-sdk/client-auto-scaling";

import { printSummary, generateSummary } from "@codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

function isValidMixedInstancesPolicy(asg: AutoScalingGroup): boolean {
	if (!asg.MixedInstancesPolicy?.LaunchTemplate?.Overrides) {
		return false;
	}

	return asg.MixedInstancesPolicy.LaunchTemplate.Overrides.length >= 2;
}

function hasMultipleAZs(asg: AutoScalingGroup): boolean {
	if (!asg.AvailabilityZones) {
		return false;
	}

	return asg.AvailabilityZones.length >= 2;
}

async function checkAutoScalingMultipleInstanceTypes(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new AutoScalingClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new DescribeAutoScalingGroupsCommand({});
		const response = await client.send(command);

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

		for (const asg of response.AutoScalingGroups) {
			if (!asg.AutoScalingGroupName || !asg.AutoScalingGroupARN) {
				results.checks.push({
					resourceName: "Unknown ASG",
					status: ComplianceStatus.ERROR,
					message: "Auto Scaling group found without name or ARN"
				});
				continue;
			}

			const hasValidMixedInstances = isValidMixedInstancesPolicy(asg);
			const hasValidAZs = hasMultipleAZs(asg);

			if (hasValidMixedInstances && hasValidAZs) {
				results.checks.push({
					resourceName: asg.AutoScalingGroupName,
					resourceArn: asg.AutoScalingGroupARN,
					status: ComplianceStatus.PASS
				});
			} else {
				const messages: string[] = [];
				if (!hasValidMixedInstances) {
					messages.push("does not use multiple instance types");
				}
				if (!hasValidAZs) {
					messages.push("does not use multiple Availability Zones");
				}

				results.checks.push({
					resourceName: asg.AutoScalingGroupName,
					resourceArn: asg.AutoScalingGroupARN,
					status: ComplianceStatus.FAIL,
					message: `Auto Scaling group ${messages.join(" and ")}`
				});
			}
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

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkAutoScalingMultipleInstanceTypes(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Auto Scaling groups should use multiple instance types in multiple Availability Zones",
	description:
		"This control checks whether Auto Scaling groups are configured to use multiple instance types across multiple Availability Zones for enhanced availability and resilience.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_AutoScaling.6",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAutoScalingMultipleInstanceTypes
} satisfies RuntimeTest;
