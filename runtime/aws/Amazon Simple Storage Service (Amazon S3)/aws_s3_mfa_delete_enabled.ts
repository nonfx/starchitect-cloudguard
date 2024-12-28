import { S3Client, GetBucketVersioningCommand, ListBucketsCommand } from "@aws-sdk/client-s3";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkS3MfaDelete(region: string = "us-east-1"): Promise<ComplianceReport> {
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

		// Check each bucket for MFA Delete
		for (const bucket of Buckets) {
			if (!bucket.Name) continue;

			try {
				const command = new GetBucketVersioningCommand({
					Bucket: bucket.Name
				});
				const response = await client.send(command);

				const isMfaDeleteEnabled = response.MFADelete === "Enabled";

				results.checks.push({
					resourceName: bucket.Name,
					resourceArn: `arn:aws:s3:::${bucket.Name}`,
					status: isMfaDeleteEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isMfaDeleteEnabled ? undefined : "MFA Delete is not enabled on this bucket"
				});
			} catch (error) {
				results.checks.push({
					resourceName: bucket.Name,
					resourceArn: `arn:aws:s3:::${bucket.Name}`,
					status: ComplianceStatus.ERROR,
					message: `Error checking bucket versioning: ${error instanceof Error ? error.message : String(error)}`
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
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkS3MfaDelete(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure MFA Delete is enabled on S3 buckets",
	description:
		"Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_2.1.2",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3MfaDelete
} satisfies RuntimeTest;
