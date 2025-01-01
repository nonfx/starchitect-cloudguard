import { EC2Client, DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkVpcExists(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all VPCs in the region
		const response = await client.send(new DescribeVpcsCommand({}));

		if (!response.Vpcs || response.Vpcs.length === 0) {
			results.checks.push({
				resourceName: "VPC Check",
				status: ComplianceStatus.FAIL,
				message: "No VPCs found in the region"
			});
			return results;
		}

		// Check each VPC
		for (const vpc of response.Vpcs) {
			if (!vpc.VpcId) {
				continue;
			}

			results.checks.push({
				resourceName: vpc.VpcId,
				resourceArn: `arn:aws:ec2:${region}:${vpc.OwnerId}:vpc/${vpc.VpcId}`,
				status: ComplianceStatus.PASS,
				message: vpc.IsDefault ? "Default VPC exists" : "Custom VPC exists"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "VPC Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking VPCs: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkVpcExists(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Amazon VPC (Virtual Private Cloud) has been created",
	description:
		"Amazon VPCs allow you to launch AWS resources into a defined virtual network, providing network isolation and controlling inbound and outbound traffic.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_2.1",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkVpcExists,
	serviceName: "Amazon Relational Database Service",
	shortServiceName: "rds"
} satisfies RuntimeTest;
