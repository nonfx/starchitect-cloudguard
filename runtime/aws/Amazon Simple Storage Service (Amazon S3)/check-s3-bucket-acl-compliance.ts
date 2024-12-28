import {
	GetBucketOwnershipControlsCommand,
	ListBucketsCommand,
	S3Client
} from "@aws-sdk/client-s3";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkS3BucketAclCompliance(region: string = "us-east-1"): Promise<ComplianceReport> {
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

		// Check each bucket's ownership controls
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
				const ownershipResponse = await client.send(
					new GetBucketOwnershipControlsCommand({
						Bucket: bucket.Name
					})
				);

				const objectOwnership = ownershipResponse.OwnershipControls?.Rules?.[0]?.ObjectOwnership;
				const isCompliant = objectOwnership === "BucketOwnerEnforced";

				results.checks.push({
					resourceName: bucket.Name,
					resourceArn: `arn:aws:s3:::${bucket.Name}`,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: "Bucket does not have ACLs disabled (ObjectOwnership is not set to BucketOwnerEnforced)"
				});
			} catch (error: any) {
				if (error.name === "NoSuchOwnershipControls") {
					results.checks.push({
						resourceName: bucket.Name,
						resourceArn: `arn:aws:s3:::${bucket.Name}`,
						status: ComplianceStatus.FAIL,
						message: "Bucket does not have ownership controls configured"
					});
				} else {
					results.checks.push({
						resourceName: bucket.Name,
						resourceArn: `arn:aws:s3:::${bucket.Name}`,
						status: ComplianceStatus.ERROR,
						message: `Error checking bucket ownership controls: ${error.message}`
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
	const results = await checkS3BucketAclCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ACLs should not be used to manage user access to S3 general purpose buckets",
	description:
		"This control checks if S3 buckets use ACLs for managing user access. ACLs are legacy access control mechanisms and bucket policies or IAM policies should be used instead.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_S3.12",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3BucketAclCompliance
} satisfies RuntimeTest;
