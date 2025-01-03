import {
	CloudFrontClient,
	ListDistributionsCommand,
	GetDistributionCommand
} from "@aws-sdk/client-cloudfront";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudFrontOACCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new CloudFrontClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all CloudFront distributions
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

		// Check each distribution
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
				// Get detailed distribution config
				const getCommand = new GetDistributionCommand({
					Id: distribution.Id
				});
				const distConfig = await client.send(getCommand);

				if (!distConfig.Distribution?.DistributionConfig?.Origins?.Items) {
					results.checks.push({
						resourceName: distribution.Id,
						resourceArn: distribution.ARN,
						status: ComplianceStatus.ERROR,
						message: "Unable to retrieve distribution origins"
					});
					continue;
				}

				// Check if distribution has S3 origins and if they use OAC
				const origins = distConfig.Distribution.DistributionConfig.Origins.Items;
				const s3Origins = origins.filter(
					origin =>
						origin.DomainName?.includes(".s3.") || origin.DomainName?.includes(".s3-website-")
				);

				if (s3Origins.length === 0) {
					results.checks.push({
						resourceName: distribution.Id,
						resourceArn: distribution.ARN,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "Distribution does not have S3 origins"
					});
					continue;
				}

				const hasOAC = s3Origins.every(origin => origin.OriginAccessControlId);

				results.checks.push({
					resourceName: distribution.Id,
					resourceArn: distribution.ARN,
					status: hasOAC ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasOAC ? undefined : "S3 origin(s) do not have Origin Access Control configured"
				});
			} catch (error) {
				results.checks.push({
					resourceName: distribution.Id,
					resourceArn: distribution.ARN,
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
	const results = await checkCloudFrontOACCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudFront distributions should use origin access control",
	description:
		"This control checks whether an Amazon CloudFront distribution with an Amazon S3 origin has origin access control (OAC) configured. The control fails if OAC isn't configured for the CloudFront distribution. When using an S3 bucket as an origin for your CloudFront distribution, you can enable OAC. This permits access to the content in the bucket only through the specified CloudFront distribution, and prohibits access directly from the bucket or another distribution. Although CloudFront supports Origin Access Identity (OAI), OAC offers additional functionality, and distributions using OAI can migrate to OAC. While OAI provides a secure way to access S3 origins, it has limitations, such as lack of support for granular policy configurations and for HTTP/HTTPS requests that use the POST method in AWS Regions that require AWS Signature Version 4 (SigV4). OAI also doesn't support encryption with AWS Key Management Service. OAC is based on an AWS best practice of using IAM service principals to authenticate with S3 origins.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.13",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudFrontOACCompliance,
	serviceName: "Amazon CloudFront",
	shortServiceName: "cloudfront"
} satisfies RuntimeTest;
