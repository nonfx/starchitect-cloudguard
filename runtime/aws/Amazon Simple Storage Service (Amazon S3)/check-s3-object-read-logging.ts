import {
	CloudTrailClient,
	GetEventSelectorsCommand,
	GetTrailCommand,
	ListTrailsCommand
} from "@aws-sdk/client-cloudtrail";
import { ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

interface Trail {
	Name?: string;
	TrailARN?: string;
}

async function checkS3ObjectReadLogging(region: string = "us-east-1"): Promise<ComplianceReport> {
	const cloudTrailClient = new CloudTrailClient({ region });
	const s3Client = new S3Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all S3 buckets
		const buckets = await s3Client.send(new ListBucketsCommand({}));
		if (!buckets.Buckets || buckets.Buckets.length === 0) {
			results.checks.push({
				resourceName: "No S3 Buckets",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No S3 buckets found"
			});
			return results;
		}

		// Get all CloudTrail trails
		const trails = await cloudTrailClient.send(new ListTrailsCommand({}));
		if (!trails.Trails || trails.Trails.length === 0) {
			results.checks = buckets.Buckets.map(bucket => ({
				resourceName: bucket.Name || "Unknown Bucket",
				status: ComplianceStatus.FAIL,
				message: "No CloudTrail trails configured to monitor S3 object-level operations"
			}));
			return results;
		}

		// Get detailed trail configurations
		const trailConfigs: Trail[] = [];
		for (const trail of trails.Trails) {
			if (trail.Name) {
				try {
					const trailConfig = await cloudTrailClient.send(
						new GetTrailCommand({ Name: trail.Name })
					);
					if (trailConfig.Trail) {
						trailConfigs.push(trailConfig.Trail);
					}
				} catch (error) {
					if (process.env.LOG_LEVEL === "debug") {
						console.error(`Error getting trail config for ${trail.Name}:`, error);
					}
				}
			}
		}

		// Check each bucket for monitoring
		for (const bucket of buckets.Buckets) {
			if (!bucket.Name) continue;

			let isMonitored = false;
			for (const trail of trailConfigs) {
				if (await isS3ObjectLoggingEnabled(cloudTrailClient, trail, bucket.Name)) {
					isMonitored = true;
					break;
				}
			}

			results.checks.push({
				resourceName: bucket.Name,
				status: isMonitored ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isMonitored
					? undefined
					: "Bucket does not have object-level read event logging enabled"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "S3 and CloudTrail Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking S3 and CloudTrail configuration: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

async function isS3ObjectLoggingEnabled(
	client: CloudTrailClient,
	trail: Trail,
	bucketName: string
): Promise<boolean> {
	if (!trail.Name) return false;

	try {
		const command = new GetEventSelectorsCommand({ TrailName: trail.Name });
		const response = await client.send(command);

		// Check traditional event selectors
		const eventSelectors = response.EventSelectors || [];
		const hasTraditionalLogging = eventSelectors.some(selector => {
			if (!selector.DataResources) return false;

			const validReadTypes = ["ReadOnly", "All"];
			if (!validReadTypes.includes(selector.ReadWriteType || "")) return false;

			return selector.DataResources.some(resource => {
				if (resource.Type !== "AWS::S3::Object") return false;

				return resource.Values?.some(
					value =>
						value === "arn:aws:s3" ||
						value === `arn:aws:s3:::${bucketName}/` ||
						value === `arn:aws:s3:::${bucketName}/*`
				);
			});
		});

		if (hasTraditionalLogging) return true;

		// Check advanced event selectors
		const advancedSelectors = response.AdvancedEventSelectors || [];
		const hasAdvancedLogging = advancedSelectors.some(selector => {
			const fieldSelectors = selector.FieldSelectors || [];

			// Need all these conditions to be true for read event logging
			const hasReadOnlyEvents = fieldSelectors.some(
				fs => fs.Field === "readOnly" && fs.Equals?.includes("true")
			);

			const hasS3ObjectEvents = fieldSelectors.some(
				fs => fs.Field === "eventCategory" && fs.Equals?.includes("Data")
			);

			const hasS3ResourceType = fieldSelectors.some(
				fs => fs.Field === "resources.type" && fs.Equals?.includes("AWS::S3::Object")
			);

			// Check if this bucket is specifically monitored
			const hasBucketArn = fieldSelectors.some(
				fs =>
					fs.Field === "resources.ARN" &&
					(fs.Equals?.some(
						arn =>
							arn === "arn:aws:s3" ||
							arn === `arn:aws:s3:::${bucketName}/` ||
							arn === `arn:aws:s3:::${bucketName}/*`
					) ||
						fs.StartsWith?.some(
							arn =>
								arn === "arn:aws:s3" ||
								arn === `arn:aws:s3:::${bucketName}/` ||
								arn === `arn:aws:s3:::${bucketName}/*`
						))
			);

			return hasReadOnlyEvents && hasS3ObjectEvents && (hasS3ResourceType || hasBucketArn);
		});

		return hasTraditionalLogging || hasAdvancedLogging;
	} catch (error) {
		if (process.env.LOG_LEVEL === "debug") {
			console.error(`Error getting event selectors for trail ${trail.Name}:`, error);
		}
		return false;
	}
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkS3ObjectReadLogging(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure that Object-level logging for read events is enabled for S3 bucket",
	description:
		"S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_3.9",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3ObjectReadLogging
} satisfies RuntimeTest;
