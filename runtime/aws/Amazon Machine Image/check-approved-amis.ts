import { EC2Client } from "@aws-sdk/client-ec2";
import { getAllAmis } from "./get-all-amis.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// List of approved AMI IDs - should be configured per organization's requirements
const APPROVED_AMIS = [
	// Add approved AMI IDs here
	"ami-example1",
	"ami-example2"
];

async function checkApprovedAMIsCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
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

		// Check each AMI against the approved list
		for (const image of images) {
			if (!image.ImageId) {
				results.checks.push({
					resourceName: "Unknown AMI",
					status: ComplianceStatus.ERROR,
					message: "AMI found without ImageId"
				});
				continue;
			}

			const isApproved = APPROVED_AMIS.includes(image.ImageId);

			results.checks.push({
				resourceName: image.Name || image.ImageId,
				resourceArn: `arn:aws:ec2:${region}::image/${image.ImageId}`,
				status: isApproved ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isApproved ? undefined : "AMI is not in the approved list"
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
	const results = await checkApprovedAMIsCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Only Approved AMIs (Images) are Used",
	description: "Ensure that all base AMIs utilized are approved for use by your organization.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.1.4",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkApprovedAMIsCompliance,
	serviceName: "Amazon Machine Image",
	shortServiceName: "ami"
} satisfies RuntimeTest;
