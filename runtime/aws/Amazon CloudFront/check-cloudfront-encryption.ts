import {
	CloudFrontClient,
	ListDistributionsCommand,
	GetDistributionCommand
} from "@aws-sdk/client-cloudfront";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudFrontEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new CloudFrontClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new ListDistributionsCommand({});
		const response = await client.send(command);

		if (!response.DistributionList?.Items || response.DistributionList.Items.length === 0) {
			results.checks.push({
				resourceName: "No CloudFront Distributions",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No CloudFront distributions found"
			});
			return results;
		}

		for (const distribution of response.DistributionList.Items) {
			if (!distribution.Id) continue;

			try {
				const getCommand = new GetDistributionCommand({ Id: distribution.Id });
				const distResponse = await client.send(getCommand);
				const config = distResponse.Distribution?.DistributionConfig;

				if (!config) {
					results.checks.push({
						resourceName: distribution.Id,
						status: ComplianceStatus.ERROR,
						message: "Could not retrieve distribution configuration"
					});
					continue;
				}

				// Check default cache behavior
				const defaultBehaviorCompliant = isValidViewerProtocolPolicy(
					config.DefaultCacheBehavior?.ViewerProtocolPolicy
				);

				// Check all cache behaviors
				const cacheBehaviorsCompliant =
					!config.CacheBehaviors?.Items ||
					config.CacheBehaviors.Items.every(behavior =>
						isValidViewerProtocolPolicy(behavior.ViewerProtocolPolicy)
					);

				const isCompliant = defaultBehaviorCompliant && cacheBehaviorsCompliant;

				results.checks.push({
					resourceName: distribution.Id,
					resourceArn: distribution.ARN,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: "Distribution allows unencrypted traffic in one or more cache behaviors"
				});
			} catch (error) {
				results.checks.push({
					resourceName: distribution.Id,
					status: ComplianceStatus.ERROR,
					message: `Error checking distribution: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "CloudFront Check",
			status: ComplianceStatus.ERROR,
			message: `Error listing distributions: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

function isValidViewerProtocolPolicy(policy?: string): boolean {
	return policy === "https-only" || policy === "redirect-to-https";
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkCloudFrontEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudFront distributions should require encryption in transit",
	description:
		"This control checks whether an Amazon CloudFront distribution requires viewers to use HTTPS directly or whether it uses redirection. The control fails if ViewerProtocolPolicy is set to allow-all for defaultCacheBehavior or for cacheBehaviors. HTTPS (TLS) can be used to help prevent potential attackers from using person-in-the-middle or similar attacks to eavesdrop on or manipulate network traffic. Only encrypted connections over HTTPS (TLS) should be allowed. Encrypting data in transit can affect performance. You should test your application with this feature to understand the performance profile and the impact of TLS.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudFrontEncryption
} satisfies RuntimeTest;
