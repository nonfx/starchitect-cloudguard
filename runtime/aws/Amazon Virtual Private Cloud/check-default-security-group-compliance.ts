import {
	DescribeSecurityGroupsCommand,
	DescribeVpcsCommand,
	EC2Client,
	type SecurityGroup
} from "@aws-sdk/client-ec2";
import { generateSummary, printSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

function isSecurityGroupCompliant(sg: SecurityGroup): boolean {
	// Check ingress rules - should either be empty or have single self-referencing rule
	const hasValidIngress =
		!sg.IpPermissions?.length ||
		(sg.IpPermissions.length === 1 &&
			sg.IpPermissions[0]?.UserIdGroupPairs?.[0]?.GroupId === sg.GroupId);

	// Check egress rules - should either be empty or have single localhost rule
	const hasValidEgress =
		!sg.IpPermissionsEgress?.length ||
		(sg.IpPermissionsEgress.length === 1 &&
			sg.IpPermissionsEgress[0]?.IpRanges?.[0]?.CidrIp === "127.0.0.1/32");

	return hasValidIngress && hasValidEgress;
}

async function checkDefaultSecurityGroupCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all VPCs
		const vpcsResponse = await client.send(new DescribeVpcsCommand({}));

		if (!vpcsResponse.Vpcs || vpcsResponse.Vpcs.length === 0) {
			results.checks.push({
				resourceName: "No VPCs",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No VPCs found in the region"
			});
			return results;
		}

		// Check each VPC's default security group
		for (const vpc of vpcsResponse.Vpcs) {
			if (!vpc.VpcId) continue;

			try {
				const sgResponse = await client.send(
					new DescribeSecurityGroupsCommand({
						Filters: [
							{ Name: "vpc-id", Values: [vpc.VpcId] },
							{ Name: "group-name", Values: ["default"] }
						]
					})
				);

				if (!sgResponse.SecurityGroups || sgResponse.SecurityGroups.length === 0) {
					results.checks.push({
						resourceName: vpc.VpcId,
						status: ComplianceStatus.ERROR,
						message: "Default security group not found"
					});
					continue;
				}

				const defaultSg = sgResponse.SecurityGroups[0];
				if (!defaultSg) {
					results.checks.push({
						resourceName: vpc.VpcId,
						status: ComplianceStatus.ERROR,
						message: "Default security group not found"
					});
					continue;
				}

				const isCompliant = isSecurityGroupCompliant(defaultSg);

				results.checks.push({
					resourceName: vpc.VpcId,
					resourceArn:
						defaultSg.GroupId && defaultSg.OwnerId
							? `arn:aws:ec2:${region}:${defaultSg.OwnerId}:security-group/${defaultSg.GroupId}`
							: undefined,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant ? undefined : "Default security group has unauthorized rules"
				});
			} catch (error) {
				results.checks.push({
					resourceName: vpc.VpcId,
					status: ComplianceStatus.ERROR,
					message: `Error checking security group: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Region Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking VPCs: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	void (async () => {
		const results = await checkDefaultSecurityGroupCompliance(region);
		printSummary(generateSummary(results));
	})();
}

export default {
	title: "Ensure the default security group of every VPC restricts all traffic",
	description:
		"A VPC comes with a default security group whose initial settings deny all inbound traffic, allow all outbound traffic, and allow all traffic between instances assigned to the security group. If you don't specify a security group when you launch an instance, the instance is automatically assigned to this default security group. Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that the default security group restrict all traffic.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_5.4",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDefaultSecurityGroupCompliance
} satisfies RuntimeTest;
