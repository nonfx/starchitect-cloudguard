import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAutoScalingELBHealthCheck(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new AutoScalingClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let groupFound = false;

		do {
			const command = new DescribeAutoScalingGroupsCommand({
				NextToken: nextToken
			});
			const response = await client.send(command);

			if (!response.AutoScalingGroups || response.AutoScalingGroups.length === 0) {
				if (!groupFound) {
					results.checks = [
						{
							resourceName: "No Auto Scaling Groups",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No Auto Scaling groups found in the region"
						}
					];
				}
				break;
			}

			for (const asg of response.AutoScalingGroups) {
				groupFound = true;
				const asgName = asg.AutoScalingGroupName || "Unknown ASG";
				const asgArn = asg.AutoScalingGroupARN;

				// Check if ASG has load balancer attached
				const hasLoadBalancer =
					(asg.LoadBalancerNames && asg.LoadBalancerNames.length > 0) ||
					(asg.TargetGroupARNs && asg.TargetGroupARNs.length > 0);

				// If no load balancer attached, mark as PASS
				if (!hasLoadBalancer) {
					results.checks.push({
						resourceName: asgName,
						resourceArn: asgArn,
						status: ComplianceStatus.PASS,
						message: "Auto Scaling group has no load balancer attached"
					});
					continue;
				}

				// Check if ELB health check is enabled
				const hasELBHealthCheck = asg.HealthCheckType === "ELB";

				results.checks.push({
					resourceName: asgName,
					resourceArn: asgArn,
					status: hasELBHealthCheck ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasELBHealthCheck
						? undefined
						: "Auto Scaling group with load balancer must use ELB health checks"
				});
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: "Auto Scaling Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Auto Scaling groups: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkAutoScalingELBHealthCheck(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Auto Scaling groups associated with a load balancer should use ELB health checks",
	description:
		"This control checks whether Auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing (ELB) health checks. The control fails if an Auto Scaling group with an attached load balancer is not using ELB health checks.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_AutoScaling.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAutoScalingELBHealthCheck,
	serviceName: "Amazon Elastic Compute Cloud (EC2)",
	shortServiceName: "ec2"
} satisfies RuntimeTest;
