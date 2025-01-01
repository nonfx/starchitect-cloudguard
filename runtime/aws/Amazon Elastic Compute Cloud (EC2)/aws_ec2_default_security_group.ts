import {
	EC2Client,
	DescribeInstancesCommand,
	DescribeSecurityGroupsCommand
} from "@aws-sdk/client-ec2";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDefaultSecurityGroupUsage(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all EC2 instances
		const instancesResponse = await client.send(new DescribeInstancesCommand({}));
		const instances = instancesResponse.Reservations?.flatMap(r => r.Instances || []) || [];

		if (instances.length === 0) {
			results.checks.push({
				resourceName: "No EC2 Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No EC2 instances found in the region"
			});
			return results;
		}

		// Get all security groups
		const securityGroupsResponse = await client.send(new DescribeSecurityGroupsCommand({}));
		const securityGroups = securityGroupsResponse.SecurityGroups || [];

		// Find default security groups
		const defaultSecurityGroups = new Set(
			securityGroups.filter(sg => sg.GroupName === "default").map(sg => sg.GroupId)
		);

		// Check each instance
		for (const instance of instances) {
			if (!instance.InstanceId) {
				continue;
			}

			const instanceSecurityGroups = instance.SecurityGroups || [];
			const usesDefaultSg = instanceSecurityGroups.some(
				sg => sg.GroupId && defaultSecurityGroups.has(sg.GroupId)
			);

			results.checks.push({
				resourceName: instance.InstanceId,
				status: usesDefaultSg ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: usesDefaultSg
					? "Instance is using default security group. Use custom security group instead."
					: undefined
			});
		}

		// Check default security groups configuration
		for (const sg of securityGroups) {
			if (sg.GroupName === "default" && sg.GroupId) {
				const hasRules =
					(sg.IpPermissions && sg.IpPermissions.length > 0) ||
					(sg.IpPermissionsEgress && sg.IpPermissionsEgress.length > 0);

				results.checks.push({
					resourceName: sg.GroupId,
					status: hasRules ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasRules ? "Default security group has active rules configured" : undefined
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "EC2 Security Groups Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking security groups: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkDefaultSecurityGroupUsage(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Default EC2 Security groups are not being used",
	description:
		"When an EC2 instance is launched a specified custom security group should be assigned to the instance",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.7",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDefaultSecurityGroupUsage,
	serviceName: "Amazon Elastic Compute Cloud (EC2)",
	shortServiceName: "ec2"
} satisfies RuntimeTest;
