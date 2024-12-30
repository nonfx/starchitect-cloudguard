import { EC2Client, DescribeImagesCommand } from "@aws-sdk/client-ec2";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAmiEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all AMIs owned by the account
		const command = new DescribeImagesCommand({
			Owners: ["self"]
		});

		const response = await client.send(command);

		if (!response.Images || response.Images.length === 0) {
			results.checks = [
				{
					resourceName: "No AMIs",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No AMIs found in the account"
				}
			];
			return results;
		}

		// Check each AMI
		for (const ami of response.Images) {
			if (!ami.ImageId) {
				results.checks.push({
					resourceName: "Unknown AMI",
					status: ComplianceStatus.ERROR,
					message: "AMI found without Image ID"
				});
				continue;
			}

			const blockDevices = ami.BlockDeviceMappings || [];
			let hasUnencryptedVolume = false;

			// Check if any block device is unencrypted
			for (const device of blockDevices) {
				if (device.Ebs && device.Ebs.Encrypted === false) {
					hasUnencryptedVolume = true;
					break;
				}
			}

			results.checks.push({
				resourceName: ami.ImageId,
				status: hasUnencryptedVolume ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: hasUnencryptedVolume ? "AMI contains unencrypted EBS volumes" : undefined
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "AMI Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking AMIs: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkAmiEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Images (AMI's) are encrypted",
	description: "Amazon Machine Images should utilize EBS Encrypted snapshots.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.1.2",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAmiEncryption,
	serviceName: "Amazon Elastic Compute Cloud (EC2)"
} satisfies RuntimeTest;
