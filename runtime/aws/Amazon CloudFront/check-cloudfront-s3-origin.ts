import { CloudFrontClient, GetDistributionCommand } from "@aws-sdk/client-cloudfront";
import { getAllCloudFrontDistributions } from "./get-all-cloudfront-distributions.js";
import { S3Client, ListBucketsCommand } from "@aws-sdk/client-s3";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudFrontS3OriginExists(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const cloudFrontClient = new CloudFrontClient({ region });
	const s3Client = new S3Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all S3 buckets
		const bucketsResponse = await s3Client.send(new ListBucketsCommand({}));
		const existingBuckets = new Set(bucketsResponse.Buckets?.map(b => b.Name) || []);

		// Get CloudFront distributions using pagination
		const distributions = (await getAllCloudFrontDistributions(cloudFrontClient)) ?? [];

		if (distributions.length === 0) {
			results.checks.push({
				resourceName: "No CloudFront Distributions",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No CloudFront distributions found"
			});
			return results;
		}

		for (const distribution of distributions) {
			if (!distribution.Id) continue;

			try {
				const distDetails = await cloudFrontClient.send(
					new GetDistributionCommand({ Id: distribution.Id })
				);

				const origins = distDetails.Distribution?.DistributionConfig?.Origins?.Items || [];
				let hasInvalidS3Origin = false;

				for (const origin of origins) {
					if (origin.DomainName?.includes(".s3.") && origin.S3OriginConfig) {
						const bucketName = origin.DomainName.split(".s3.")[0];
						if (!existingBuckets.has(bucketName)) {
							hasInvalidS3Origin = true;
							break;
						}
					}
				}

				results.checks.push({
					resourceName: distribution.Id,
					resourceArn: distribution.ARN,
					status: hasInvalidS3Origin ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasInvalidS3Origin
						? "CloudFront distribution points to non-existent S3 bucket"
						: undefined
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
	const results = await checkCloudFrontS3OriginExists(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudFront distributions should not point to non-existent S3 origins",
	description:
		"This control checks whether Amazon CloudFront distributions are pointing to non-existent Amazon S3 origins. The control fails for a CloudFront distribution if the origin is configured to point to a non-existent bucket. This control only applies to CloudFront distributions where an S3 bucket without static website hosting is the S3 origin. When a CloudFront distribution in your account is configured to point to a non-existent bucket, a malicious third party can create the referenced bucket and serve their own content through your distribution. We recommend checking all origins regardless of routing behavior to ensure that your distributions are pointing to appropriate origins.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFront.12",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "CRITICAL",
	execute: checkCloudFrontS3OriginExists,
	serviceName: "Amazon CloudFront",
	shortServiceName: "cloudfront"
} satisfies RuntimeTest;
