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

		// Check each AMI for encryption
		for (const image of response.Images) {
			if (!image.ImageId) {
				results.checks.push({
					resourceName: "Unknown AMI",
					status: ComplianceStatus.ERROR,
					message: "AMI found without ImageId"
				});
				continue;
			}

			const isEncrypted = image.BlockDeviceMappings?.every(
				mapping => mapping.Ebs?.Encrypted === true
			);

			results.checks.push({
				resourceName: image.ImageId,
				resourceArn: `arn:aws:ec2:${region}::image/${image.ImageId}`,
				status: isEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isEncrypted ? undefined : "AMI contains unencrypted EBS snapshots"
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
	const region = process.env.AWS_REGION;
	const results = await checkAmiEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Images (AMI's) are encrypted",
	description: "Amazon Machine Images should utilize EBS Encrypted snapshots",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.1.1",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkAmiEncryption,
	serviceName: "Amazon Machine Image",
	shortServiceName: "ami"
} satisfies RuntimeTest;
