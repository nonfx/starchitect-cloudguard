import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkAutoScalingTagPropagation(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new AutoScalingClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let asgFound = false;

		do {
			const command = new DescribeAutoScalingGroupsCommand({
				NextToken: nextToken
			});
			const response = await client.send(command);

			if (!response.AutoScalingGroups || response.AutoScalingGroups.length === 0) {
				if (!asgFound) {
					results.checks = [
						{
							resourceName: "No Auto Scaling Groups",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No Auto Scaling Groups found in the region"
						}
					];
					return results;
				}
				break;
			}

			asgFound = true;
			for (const asg of response.AutoScalingGroups) {
				if (!asg.AutoScalingGroupName || !asg.AutoScalingGroupARN) {
					results.checks.push({
						resourceName: "Unknown ASG",
						status: ComplianceStatus.ERROR,
						message: "Auto Scaling Group found without name or ARN"
					});
					continue;
				}

				// Check if any tags are set to not propagate
				const nonPropagatingTags = asg.Tags?.filter(tag => !tag.PropagateAtLaunch) || [];

				results.checks.push({
					resourceName: asg.AutoScalingGroupName,
					resourceArn: asg.AutoScalingGroupARN,
					status: nonPropagatingTags.length === 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message:
						nonPropagatingTags.length > 0
							? `${nonPropagatingTags.length} tags are not set to propagate to EC2 instances`
							: undefined
				});
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Auto Scaling Groups: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkAutoScalingTagPropagation(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure EC2 Auto Scaling Groups Propagate Tags to EC2 Instances that it launches",
	description:
		"Tags can help with managing, identifying, organizing, searching for, and filtering resources. Additionally, tags can help with security and compliance. Tags can be propagated from an Auto Scaling group to the EC2 instances that it launches.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.14",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAutoScalingTagPropagation
} satisfies RuntimeTest;
