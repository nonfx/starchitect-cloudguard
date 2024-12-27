import {
	EC2Client,
	DescribeLaunchTemplatesCommand,
	DescribeLaunchTemplateVersionsCommand
} from "@aws-sdk/client-ec2";

import { printSummary, generateSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkEc2LaunchTemplateImdsv2Compliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all launch templates
		const templatesResponse = await client.send(new DescribeLaunchTemplatesCommand({}));

		if (!templatesResponse.LaunchTemplates || templatesResponse.LaunchTemplates.length === 0) {
			results.checks = [
				{
					resourceName: "No Launch Templates",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No EC2 launch templates found in the region"
				}
			];
			return results;
		}

		// Check each launch template
		for (const template of templatesResponse.LaunchTemplates) {
			if (!template.LaunchTemplateId || !template.LaunchTemplateName) {
				results.checks.push({
					resourceName: "Unknown Template",
					status: ComplianceStatus.ERROR,
					message: "Launch template found without ID or name"
				});
				continue;
			}

			try {
				// Get the default version of the launch template
				const versionResponse = await client.send(
					new DescribeLaunchTemplateVersionsCommand({
						LaunchTemplateId: template.LaunchTemplateId,
						Versions: ["$Default"]
					})
				);

				if (!versionResponse.LaunchTemplateVersions?.[0]?.LaunchTemplateData) {
					results.checks.push({
						resourceName: template.LaunchTemplateName,
						status: ComplianceStatus.ERROR,
						message: "Unable to retrieve launch template data"
					});
					continue;
				}

				const templateData = versionResponse.LaunchTemplateVersions[0].LaunchTemplateData;
				const metadataOptions = templateData.MetadataOptions;

				// Check if IMDSv2 is required
				const isCompliant = metadataOptions?.HttpTokens === "required";

				results.checks.push({
					resourceName: template.LaunchTemplateName,
					resourceArn: `arn:aws:ec2:${region}:launch-template/${template.LaunchTemplateId}`,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: "Launch template does not require IMDSv2 (HttpTokens is not set to required)"
				});
			} catch (error) {
				results.checks.push({
					resourceName: template.LaunchTemplateName,
					status: ComplianceStatus.ERROR,
					message: `Error checking launch template version: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking launch templates: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEc2LaunchTemplateImdsv2Compliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "EC2 launch templates should use Instance Metadata Service Version 2 (IMDSv2)",
	description:
		"This control checks if EC2 launch templates are configured to use IMDSv2. IMDSv2 provides enhanced security through token-based authentication for instance metadata requests.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.170",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEc2LaunchTemplateImdsv2Compliance
} satisfies RuntimeTest;
