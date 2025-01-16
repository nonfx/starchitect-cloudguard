import { CloudFrontClient } from "@aws-sdk/client-cloudfront";
import { getAllCloudFrontDistributions } from "../../utils/aws/get-all-cloudfront-distributions.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudFrontCustomSSLCertificate(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new CloudFrontClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const distributions = (await getAllCloudFrontDistributions(client)) ?? [];

		if (distributions.length === 0) {
			results.checks.push({
				resourceName: "No CloudFront Distributions",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No CloudFront distributions found"
			});
			return results;
		}

		for (const distribution of distributions) {
			if (!distribution.Id || !distribution.ARN) {
				results.checks.push({
					resourceName: "Unknown Distribution",
					status: ComplianceStatus.ERROR,
					message: "Distribution found without ID or ARN"
				});
				continue;
			}

			const isUsingCustomCertificate =
				!distribution.ViewerCertificate?.CloudFrontDefaultCertificate;

			results.checks.push({
				resourceName: distribution.Id,
				resourceArn: distribution.ARN,
				status: isUsingCustomCertificate ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isUsingCustomCertificate
					? undefined
					: "CloudFront distribution is using the default SSL/TLS certificate instead of a custom certificate"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "CloudFront Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking CloudFront distributions: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkCloudFrontCustomSSLCertificate(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudFront distributions should use custom SSL/TLS certificates",
	description:
		"This control checks whether CloudFront distributions are using the default SSL/TLS certificate CloudFront provides. This control passes if the CloudFront distribution uses a custom SSL/TLS certificate. This control fails if the CloudFront distribution uses the default SSL/TLS certificate. Custom SSL/TLS allow your users to access content by using alternate domain names. You can store custom certificates in AWS Certificate Manager (recommended), or in IAM",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.7",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudFrontCustomSSLCertificate,
	serviceName: "Amazon CloudFront",
	shortServiceName: "cloudfront"
} satisfies RuntimeTest;
