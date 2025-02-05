import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudTrailLogValidation(
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

		// Check each trail for log validation
		for (const trail of response.trailList) {
			if (!trail.Name || !trail.TrailARN) {
				results.checks.push({
					resourceName: "Unknown Trail",
					status: ComplianceStatus.ERROR,
					message: "Trail found without name or ARN"
				});
				continue;
			}

			results.checks.push({
				resourceName: trail.Name,
				resourceArn: trail.TrailARN,
				status: trail.LogFileValidationEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: trail.LogFileValidationEnabled
					? undefined
					: "CloudTrail log file validation is not enabled"
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
	const results = await checkCloudTrailLogValidation(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure CloudTrail log file validation is enabled",
	description:
		"CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was changed, deleted, or unchanged after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_3.2",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		},
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudTrailLogValidation,
	serviceName: "AWS CloudTrail",
	shortServiceName: "cloudtrail"
} satisfies RuntimeTest;
