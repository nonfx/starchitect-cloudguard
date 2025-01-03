import {
	CloudFrontClient,
	ListDistributionsCommand,
	GetDistributionCommand
} from "@aws-sdk/client-cloudfront";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudFrontLoggingCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new CloudFrontClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get list of all CloudFront distributions
		const listCommand = new ListDistributionsCommand({});
		const response = await client.send(listCommand);

		if (!response.DistributionList?.Items || response.DistributionList.Items.length === 0) {
			results.checks = [
				{
					resourceName: "No CloudFront Distributions",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No CloudFront distributions found"
				}
			];
			return results;
		}

		// Check each distribution for logging configuration
		for (const distribution of response.DistributionList.Items) {
			if (!distribution.Id) {
				results.checks.push({
					resourceName: "Unknown Distribution",
					status: ComplianceStatus.ERROR,
					message: "Distribution found without ID"
				});
				continue;
			}

			try {
				const getCommand = new GetDistributionCommand({
					Id: distribution.Id
				});
				const distConfig = await client.send(getCommand);

				const hasLogging = distConfig.Distribution?.DistributionConfig?.Logging?.Bucket;
				const distributionArn = `arn:aws:cloudfront::${distribution.Id}`;

				results.checks.push({
					resourceName: distribution.Id,
					resourceArn: distributionArn,
					status: hasLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasLogging ? undefined : "CloudFront distribution does not have logging enabled"
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
		results.checks = [
			{
				resourceName: "CloudFront Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking CloudFront distributions: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkCloudFrontLoggingCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudFront distributions should have logging enabled",
	description:
		"This control checks whether server access logging is enabled on CloudFront distributions. The control fails if access logging is not enabled for a distribution. CloudFront access logs provide detailed information about every user request that CloudFront receives. Each log contains information such as the date and time the request was received, the IP address of the viewer that made the request, the source of the request, and the port number of the request from the viewer. These logs are useful for applications such as security and access audits and forensics investigation",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudFrontLoggingCompliance,
	serviceName: "Amazon CloudFront",
	shortServiceName: "cloudfront"
} satisfies RuntimeTest;
