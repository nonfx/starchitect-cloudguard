import {
	CloudTrailClient,
	GetEventSelectorsCommand,
	GetTrailCommand,
	ListTrailsCommand
} from "@aws-sdk/client-cloudtrail";
import { ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface Trail {
	Name?: string;
	TrailARN?: string;
}

async function checkS3ObjectLevelLogging(region: string = "us-east-1"): Promise<ComplianceReport> {
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
		const trails: Trail[] = [];
		let nextToken: string | undefined;
		do {
			const listResponse = await cloudTrailClient.send(
				new ListTrailsCommand({ NextToken: nextToken })
			);

			if (listResponse.Trails) {
				for (const trail of listResponse.Trails) {
					if (trail.Name) {
						const detailResponse = await cloudTrailClient.send(
							new GetTrailCommand({ Name: trail.Name })
						);
						if (detailResponse.Trail) {
							trails.push(detailResponse.Trail as Trail);
						}
					}
				}
			}

			nextToken = listResponse.NextToken;
		} while (nextToken);

		// Check each bucket for object-level logging
		for (const bucket of buckets.Buckets) {
			const bucketName = bucket.Name;
			if (!bucketName) continue;

			let isMonitored = false;
			for (const trail of trails) {
				if (await isTrailMonitoringBucket(cloudTrailClient, trail, bucketName)) {
					isMonitored = true;
					break;
				}
			}

			results.checks.push({
				resourceName: bucketName,
				status: isMonitored ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isMonitored
					? undefined
					: "Bucket does not have object-level logging enabled for write events"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "S3 and CloudTrail Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking S3 object-level logging: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

async function isTrailMonitoringBucket(
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

			const validWriteTypes = ["WriteOnly", "All"];
			if (!validWriteTypes.includes(selector.ReadWriteType || "")) return false;

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

			// Need these conditions for write event logging
			const hasWriteOnlyEvents = fieldSelectors.some(
				fs => fs.Field === "readOnly" && fs.Equals?.includes("false")
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

			return hasWriteOnlyEvents && hasS3ObjectEvents && (hasS3ResourceType || hasBucketArn);
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
	const results = await checkS3ObjectLevelLogging(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure that Object-level logging for write events is enabled for S3 bucket",
	description:
		"S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_3.8",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3ObjectLevelLogging,
	serviceName: "Amazon Simple Storage Service (Amazon S3)",
	shortServiceName: "s3"
} satisfies RuntimeTest;
