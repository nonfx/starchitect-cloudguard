import { EC2Client } from "@aws-sdk/client-ec2";
import { getAllAmis } from "./get-all-amis.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAmiAge(region: string = "us-east-1"): Promise<ComplianceReport> {
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

		const ninetyDaysAgo = new Date();
		ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);

		for (const image of images) {
			if (!image.ImageId || !image.CreationDate) {
				results.checks.push({
					resourceName: image.ImageId || "Unknown AMI",
					status: ComplianceStatus.ERROR,
					message: "AMI missing required information"
				});
				continue;
			}

			const creationDate = new Date(image.CreationDate);
			const isCompliant = creationDate >= ninetyDaysAgo;

			results.checks.push({
				resourceName: image.ImageId,
				resourceArn: `arn:aws:ec2:${region}::image/${image.ImageId}`,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant
					? undefined
					: `AMI is older than 90 days (created on ${image.CreationDate})`
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
	const results = await checkAmiAge(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Images (AMI) are not older than 90 days",
	description: "Ensure that your AMIs are not older than 90 days.",
	controls: [
		{
			id: "AWS-Security-Best-Practices_v1.0.0_AMI.1",
			document: "AWS-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAmiAge,
	serviceName: "Amazon Machine Image",
	shortServiceName: "ami"
} satisfies RuntimeTest;
