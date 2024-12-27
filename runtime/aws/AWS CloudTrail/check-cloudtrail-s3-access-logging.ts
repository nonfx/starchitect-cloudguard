import { CloudTrailClient, GetTrailCommand, ListTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { GetBucketLoggingCommand, S3Client } from "@aws-sdk/client-s3";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkCloudTrailS3AccessLogging(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const s3Client = new S3Client({ region });
	const cloudTrailClient = new CloudTrailClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all CloudTrail trails
		const listTrailsResponse = await cloudTrailClient.send(new ListTrailsCommand({}));

		if (!listTrailsResponse.Trails || listTrailsResponse.Trails.length === 0) {
			results.checks.push({
				resourceName: "No CloudTrails",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No CloudTrail trails found in the region"
			});
			return results;
		}

		// Check each trail's S3 bucket
		for (const trail of listTrailsResponse.Trails) {
			if (!trail.TrailARN) continue;

			try {
				// Get detailed trail information
				const trailDetails = await cloudTrailClient.send(
					new GetTrailCommand({ Name: trail.TrailARN })
				);

				if (!trailDetails.Trail?.S3BucketName) {
					results.checks.push({
						resourceName: trail.Name || "Unknown Trail",
						resourceArn: trail.TrailARN,
						status: ComplianceStatus.ERROR,
						message: "Trail has no S3 bucket configured"
					});
					continue;
				}

				try {
					// Check if bucket logging is enabled
					const loggingStatus = await s3Client.send(
						new GetBucketLoggingCommand({
							Bucket: trailDetails.Trail.S3BucketName
						})
					);

					const hasLogging = !!loggingStatus.LoggingEnabled;

					results.checks.push({
						resourceName: trailDetails.Trail.S3BucketName,
						resourceArn: trail.TrailARN,
						status: hasLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: hasLogging
							? undefined
							: "CloudTrail S3 bucket does not have access logging enabled"
					});
				} catch (error) {
					results.checks.push({
						resourceName: trailDetails.Trail.S3BucketName,
						resourceArn: trail.TrailARN,
						status: ComplianceStatus.ERROR,
						message: `Error checking bucket logging: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: trail.Name || "Unknown Trail",
					resourceArn: trail.TrailARN,
					status: ComplianceStatus.ERROR,
					message: `Error getting trail details: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "CloudTrail Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking CloudTrail trails: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkCloudTrailS3AccessLogging(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
	description:
		"S3 Bucket Access Logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_3.4",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		},
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.7",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudTrailS3AccessLogging
} satisfies RuntimeTest;
