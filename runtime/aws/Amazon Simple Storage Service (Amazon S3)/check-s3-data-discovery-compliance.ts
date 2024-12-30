import {
	DescribeBucketsCommand,
	GetAutomatedDiscoveryConfigurationCommand,
	Macie2Client
} from "@aws-sdk/client-macie2";
import { ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkS3DataDiscoveryCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const macieClient = new Macie2Client({ region });
	const s3Client = new S3Client({ region });

	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check if automated discovery is enabled
		const discoveryConfig = await macieClient.send(
			new GetAutomatedDiscoveryConfigurationCommand({})
		);
		const isDiscoveryEnabled = discoveryConfig.status === "ENABLED";

		// Get all S3 buckets
		const listBucketsResponse = await s3Client.send(new ListBucketsCommand({}));
		const buckets = listBucketsResponse.Buckets || [];

		if (buckets.length === 0) {
			results.checks.push({
				resourceName: "No S3 Buckets",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No S3 buckets found in the account"
			});
			return results;
		}

		// If discovery is not enabled, mark all buckets as non-compliant
		if (!isDiscoveryEnabled) {
			results.checks.push({
				resourceName: "Macie Automated Discovery",
				status: ComplianceStatus.FAIL,
				message: "Automated sensitive data discovery is not enabled"
			});

			for (const bucket of buckets) {
				if (!bucket.Name) continue;

				results.checks.push({
					resourceName: bucket.Name,
					resourceArn: `arn:aws:s3:::${bucket.Name}`,
					status: ComplianceStatus.FAIL,
					message: "Automated sensitive data discovery is not enabled for the account"
				});
			}
			return results;
		}

		// Get buckets monitored by Macie
		const describeBucketsResponse = await macieClient.send(new DescribeBucketsCommand({}));
		const monitoredBuckets = new Set(
			describeBucketsResponse.buckets?.map(bucket => bucket.bucketName) || []
		);

		// Check each bucket's monitoring status
		for (const bucket of buckets) {
			if (!bucket.Name) continue;

			const isMonitored = monitoredBuckets.has(bucket.Name);
			results.checks.push({
				resourceName: bucket.Name,
				resourceArn: `arn:aws:s3:::${bucket.Name}`,
				status: isMonitored ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isMonitored
					? "Bucket is configured for automated sensitive data discovery"
					: "Bucket is not configured for automated sensitive data discovery"
			});
		}

		// Add summary of automated discovery configuration
		results.checks.push({
			resourceName: "Macie Automated Discovery",
			status: ComplianceStatus.PASS,
			message: `Automated sensitive data discovery is enabled${discoveryConfig.autoEnableOrganizationMembers ? ` (Organization mode: ${discoveryConfig.autoEnableOrganizationMembers})` : ""}`
		});
	} catch (error) {
		results.checks.push({
			resourceName: "S3 Discovery Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking S3 data discovery: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkS3DataDiscoveryCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure all data in Amazon S3 has been discovered, classified, and secured when required",
	description:
		"Amazon S3 buckets can contain sensitive data, that for security purposes should be discovered, monitored, classified and protected. Macie along with other 3rd party tools can automatically provide an inventory of Amazon S3 buckets.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_2.1.3",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3DataDiscoveryCompliance,
	serviceName: "Amazon Simple Storage Service (Amazon S3)"
} satisfies RuntimeTest;
