import { EC2Client } from "@aws-sdk/client-ec2";
import { getAllAmis } from "../../utils/aws/get-all-amis.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkPublicAMIs(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all AMIs owned by the account using pagination
		const images = (await getAllAmis(client, [{ Name: "owner-alias", Values: ["self"] }])) ?? [];

		if (images.length === 0) {
			results.checks = [
				{
					resourceName: "No AMIs",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No AMIs found in the account"
				}
			];
			return results;
		}

		// Check each AMI's public accessibility
		for (const image of images) {
			if (!image.ImageId) {
				results.checks.push({
					resourceName: "Unknown AMI",
					status: ComplianceStatus.ERROR,
					message: "AMI found without ImageId"
				});
				continue;
			}

			const isPublic = image.Public === true;

			results.checks.push({
				resourceName: image.ImageId,
				resourceArn: `arn:aws:ec2:${region}::image/${image.ImageId}`,
				status: isPublic ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: isPublic ? "AMI is publicly accessible" : undefined
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
	const results = await checkPublicAMIs(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Images are not Publicly Available",
	description: "EC2 allows you to make an AMI public, sharing it with all AWS accounts",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.1.5",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkPublicAMIs,
	serviceName: "Amazon Machine Image",
	shortServiceName: "ami"
} satisfies RuntimeTest;
