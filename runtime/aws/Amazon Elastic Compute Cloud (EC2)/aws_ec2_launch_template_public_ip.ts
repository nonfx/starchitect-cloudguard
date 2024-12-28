import {
	EC2Client,
	DescribeLaunchTemplatesCommand,
	DescribeLaunchTemplateVersionsCommand
} from "@aws-sdk/client-ec2";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkLaunchTemplatePublicIp(
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
			results.checks.push({
				resourceName: "No Launch Templates",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No EC2 launch templates found in the region"
			});
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
				const hasPublicIp = templateData.NetworkInterfaces?.some(
					ni => ni.AssociatePublicIpAddress === true
				);

				results.checks.push({
					resourceName: template.LaunchTemplateName,
					resourceArn: `arn:aws:ec2:${region}:launch-template/${template.LaunchTemplateId}`,
					status: hasPublicIp ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasPublicIp
						? "Launch template assigns public IP addresses to network interfaces"
						: undefined
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
		results.checks.push({
			resourceName: "Region Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking launch templates: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkLaunchTemplatePublicIp(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Amazon EC2 launch templates should not assign public IPs to network interfaces",
	description:
		"This control checks whether EC2 launch templates are configured to assign public IP addresses to network interfaces. Assigning public IPs directly exposes instances to the internet and increases security risks.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.25",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkLaunchTemplatePublicIp
} satisfies RuntimeTest;
