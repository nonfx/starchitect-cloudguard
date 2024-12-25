import { GetPublicAccessBlockCommand, ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkS3BlockPublicAccess(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new S3Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// List all buckets
		const { Buckets } = await client.send(new ListBucketsCommand({}));

		if (!Buckets || Buckets.length === 0) {
			results.checks = [
				{
					resourceName: "No S3 Buckets",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No S3 buckets found in the account"
				}
			];
			return results;
		}

		// Check each bucket
		for (const bucket of Buckets) {
			if (!bucket.Name) continue;

			try {
				// Check public access block configuration
				const publicAccessBlock = await client.send(
					new GetPublicAccessBlockCommand({ Bucket: bucket.Name })
				);

				const blockConfig = publicAccessBlock.PublicAccessBlockConfiguration;
				if (!blockConfig) {
					results.checks.push({
						resourceName: bucket.Name,
						resourceArn: `arn:aws:s3:::${bucket.Name}`,
						status: ComplianceStatus.FAIL,
						message: "No public access block configuration found for bucket"
					});
					continue;
				}

				const isFullyBlocked =
					blockConfig.BlockPublicAcls &&
					blockConfig.BlockPublicPolicy &&
					blockConfig.IgnorePublicAcls &&
					blockConfig.RestrictPublicBuckets;

				results.checks.push({
					resourceName: bucket.Name,
					resourceArn: `arn:aws:s3:::${bucket.Name}`,
					status: isFullyBlocked ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isFullyBlocked
						? undefined
						: "Bucket does not have all public access block settings enabled"
				});
			} catch (error: any) {
				// Handle NoSuchPublicAccessBlockConfiguration as FAIL
				if (error.name === "NoSuchPublicAccessBlockConfiguration") {
					results.checks.push({
						resourceName: bucket.Name,
						resourceArn: `arn:aws:s3:::${bucket.Name}`,
						status: ComplianceStatus.FAIL,
						message: "No public access block configuration found for bucket"
					});
				} else {
					results.checks.push({
						resourceName: bucket.Name,
						resourceArn: `arn:aws:s3:::${bucket.Name}`,
						status: ComplianceStatus.ERROR,
						message: `Error checking bucket public access block: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "S3 Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking S3 buckets: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkS3BlockPublicAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'",
	description:
		"Amazon S3 provides Block public access (bucket settings) and Block public access (account settings) to help you manage public access to Amazon S3 resources. By default, S3 buckets and objects are created with public access disabled. However, an IAM principle with sufficient S3 permissions can enable public access at the bucket and/or object level. While enabled, Block public access (bucket settings) prevents an individual bucket, and its contained objects, from becoming publicly accessible. Similarly, Block public access (account settings) prevents all buckets, and contained objects, from becoming publicly accessible across the entire account.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_2.1.4",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3BlockPublicAccess
} satisfies RuntimeTest;
