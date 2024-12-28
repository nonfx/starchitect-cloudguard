import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudTrailKmsEncryption(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new CloudTrailClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all CloudTrail trails
		const response = await client.send(new DescribeTrailsCommand({}));

		if (!response.trailList || response.trailList.length === 0) {
			results.checks = [
				{
					resourceName: "No CloudTrails",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No CloudTrail trails found in the region"
				}
			];
			return results;
		}

		// Check each trail for KMS encryption
		for (const trail of response.trailList) {
			if (!trail.Name) {
				results.checks.push({
					resourceName: "Unknown Trail",
					status: ComplianceStatus.ERROR,
					message: "Trail found without name"
				});
				continue;
			}

			const hasKmsKey = !!trail.KmsKeyId;

			results.checks.push({
				resourceName: trail.Name,
				resourceArn: trail.TrailARN,
				status: hasKmsKey ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasKmsKey ? undefined : "CloudTrail is not configured to use SSE-KMS encryption"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "CloudTrail Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking CloudTrail trails: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkCloudTrailKmsEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
	description:
		"AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer created master keys (CMK) to further protect CloudTrail logs. It is recommended that CloudTrail be configured to use SSE-KMS.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_3.5",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudTrailKmsEncryption
} satisfies RuntimeTest;
