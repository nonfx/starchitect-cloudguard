import {
	GetBucketLifecycleConfigurationCommand,
	ListBucketsCommand,
	S3Client
} from "@aws-sdk/client-s3";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkS3BucketLifecycleConfiguration(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new S3Client({ region });
	const results: ComplianceReport = {
		checks: []
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

		// Check each bucket for lifecycle configuration
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
				// Get bucket lifecycle configuration
				const lifecycleCommand = new GetBucketLifecycleConfigurationCommand({
					Bucket: bucket.Name
				});

				const lifecycleResponse = await client.send(lifecycleCommand);

				// Check if there are any enabled lifecycle rules
				const hasEnabledRules = lifecycleResponse.Rules?.some(rule => rule.Status === "Enabled");

				results.checks.push({
					resourceName: bucket.Name,
					resourceArn: `arn:aws:s3:::${bucket.Name}`,
					status: hasEnabledRules ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasEnabledRules ? undefined : "Bucket does not have any enabled lifecycle rules"
				});
			} catch (error: any) {
				if (error.name === "NoSuchLifecycleConfiguration") {
					results.checks.push({
						resourceName: bucket.Name,
						resourceArn: `arn:aws:s3:::${bucket.Name}`,
						status: ComplianceStatus.FAIL,
						message: "No lifecycle configuration found for the bucket"
					});
				} else {
					results.checks.push({
						resourceName: bucket.Name,
						resourceArn: `arn:aws:s3:::${bucket.Name}`,
						status: ComplianceStatus.ERROR,
						message: `Error checking lifecycle configuration: ${error.message}`
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
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkS3BucketLifecycleConfiguration(region);
	printSummary(generateSummary(results));
}

export default {
	title: "S3 general purpose buckets should have Lifecycle configurations",
	description:
		"This control checks whether S3 buckets have Lifecycle configurations enabled to manage object transitions and deletions effectively.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_S3.13",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3BucketLifecycleConfiguration,
	serviceName: "Amazon Simple Storage Service (Amazon S3)",
	shortServiceName: "s3"
} satisfies RuntimeTest;
