import { S3Client, ListBucketsCommand, GetBucketLoggingCommand } from "@aws-sdk/client-s3";

import {
	printSummary,
	generateSummary,
	type ComplianceReport,
	ComplianceStatus
} from "@codegen/utils/stringUtils";

async function checkS3BucketLogging(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new S3Client({ region });
	const results: ComplianceReport = {
		checks: [],
		metadoc: {
			title: "S3 general purpose buckets should have server access logging enabled",
			description:
				"This control checks whether server access logging is enabled for S3 buckets. Server access logging provides detailed records of requests made to buckets and assists in security audits.",
			controls: [
				{
					id: "AWS-Foundational-Security-Best-Practices_v1.0.0_S3.9",
					document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
				}
			]
		}
	};

	try {
		// Get all S3 buckets
		const listBucketsResponse = await client.send(new ListBucketsCommand({}));

		if (!listBucketsResponse.Buckets || listBucketsResponse.Buckets.length === 0) {
			results.checks = [
				{
					resourceName: "No S3 Buckets",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No S3 buckets found in the account"
				}
			];
			return results;
		}

		// Check each bucket for logging configuration
		for (const bucket of listBucketsResponse.Buckets) {
			if (!bucket.Name) {
				results.checks.push({
					resourceName: "Unknown Bucket",
					status: ComplianceStatus.ERROR,
					message: "Bucket found without name"
				});
				continue;
			}

			try {
				// Get bucket logging configuration
				const loggingResponse = await client.send(
					new GetBucketLoggingCommand({ Bucket: bucket.Name })
				);

				const hasLogging = !!loggingResponse.LoggingEnabled;

				results.checks.push({
					resourceName: bucket.Name,
					resourceArn: `arn:aws:s3:::${bucket.Name}`,
					status: hasLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasLogging ? undefined : "Server access logging is not enabled for this bucket"
				});
			} catch (error) {
				results.checks.push({
					resourceName: bucket.Name,
					resourceArn: `arn:aws:s3:::${bucket.Name}`,
					status: ComplianceStatus.ERROR,
					message: `Error checking bucket logging: ${error instanceof Error ? error.message : String(error)}`
				});
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
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkS3BucketLogging(region);
	printSummary(generateSummary(results));
}

export default checkS3BucketLogging;
