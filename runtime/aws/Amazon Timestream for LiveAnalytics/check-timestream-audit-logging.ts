import {
	CloudTrailClient,
	GetTrailCommand,
	GetEventSelectorsCommand,
	ListTrailsCommand,
	type TrailInfo,
	type Trail,
	type EventSelector,
	type AdvancedEventSelector
} from "@aws-sdk/client-cloudtrail";
import {
	TimestreamWriteClient,
	ListDatabasesCommand,
	type Database
} from "@aws-sdk/client-timestream-write";
import { S3Client, GetBucketLoggingCommand, GetBucketEncryptionCommand } from "@aws-sdk/client-s3";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllTimestreamDatabases } from "./get-all-timestream-databases.js";

async function checkTimestreamAuditLogging(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const cloudtrailClient = new CloudTrailClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Fetch all Timestream databases
		const databases: Database[] = await getAllTimestreamDatabases(region);

		if (databases.length === 0) {
			results.checks.push({
				resourceName: "No Timestream Databases",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Timestream databases found in the region"
			});
			return results;
		}

		// Get all CloudTrail trails
		let trails = [];
		let nextToken: string | undefined;

		do {
			const listResponse = await cloudtrailClient.send(
				new ListTrailsCommand({ NextToken: nextToken })
			);
			if (listResponse.Trails) trails.push(...listResponse.Trails);
			nextToken = listResponse.NextToken;
		} while (nextToken);

		if (trails.length === 0) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.FAIL,
				message: "No CloudTrail trails configured"
			});
			return results;
		}

		let isCompliant = false;
		let resultantTrail: TrailInfo = {};
		for (const trail of trails) {
			if (!trail.TrailARN || !trail.Name) continue;

			const trailDetails = await cloudtrailClient.send(
				new GetTrailCommand({
					Name: trail.Name
				})
			);

			if (!trailDetails.Trail) continue;

			// Get event selectors for the trail
			const eventSelectorsResponse = await cloudtrailClient.send(
				new GetEventSelectorsCommand({
					TrailName: trail.TrailARN
				})
			);

			// Check if the trail has management events enabled
			const hasManagementEvents =
				eventSelectorsResponse.EventSelectors?.some(
					(selector: EventSelector) =>
						selector.IncludeManagementEvents === true &&
						(!selector.ReadWriteType ||
							selector.ReadWriteType === "All" ||
							selector.ReadWriteType === "WriteOnly")
				) ||
				eventSelectorsResponse.AdvancedEventSelectors?.some((selector: AdvancedEventSelector) =>
					selector.FieldSelectors?.some(
						field => field.Field === "eventCategory" && field.Equals?.includes("Management")
					)
				);

			// Check if the trail has specific Timestream data event logging
			const hasTimestreamDataEvents =
				eventSelectorsResponse.EventSelectors?.some((selector: EventSelector) =>
					selector.DataResources?.some(
						resource =>
							resource.Type === "AWS::Timestream::Table" &&
							(resource.Values?.includes("*") ||
								resource.Values?.some(v => v.includes("timestream")))
					)
				) ||
				eventSelectorsResponse.AdvancedEventSelectors?.some((selector: AdvancedEventSelector) =>
					selector.FieldSelectors?.some(
						field =>
							(field.Field === "eventSource" &&
								field.Equals?.some(source => source.includes("timestream"))) ||
							(field.Field === "resources.type" && field.Equals?.includes("AWS::Timestream::Table"))
					)
				) ||
				eventSelectorsResponse.AdvancedEventSelectors?.some((selector: AdvancedEventSelector) =>
					selector.FieldSelectors?.some(
						field =>
							(field.Field === "eventSource" &&
								field.Equals?.some(source => source.includes("timestream"))) ||
							(field.Field === "resources.type" &&
								field.Equals?.includes("AWS::Timestream::Database"))
					)
				);

			const hasEncryption = !!trailDetails.Trail.KmsKeyId;
			const hasCloudWatchLogs = !!trailDetails.Trail.CloudWatchLogsLogGroupArn;
			const isMultiRegion = !!trailDetails.Trail.IsMultiRegionTrail;

			// Trail is compliant if it has either management events or specific Timestream data events,
			// plus encryption and CloudWatch logs integration
			isCompliant = !!(
				(hasManagementEvents || hasTimestreamDataEvents) &&
				hasEncryption &&
				hasCloudWatchLogs &&
				isMultiRegion
			);
			resultantTrail = trail;
			if (isCompliant) {
				break;
			}
		}

		results.checks.push({
			resourceName: resultantTrail.Name || "Unknown Trail",
			resourceArn: resultantTrail.TrailARN,
			status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
			message: isCompliant
				? undefined
				: "No compliant trail found. Trails must have management events or Timestream data events enabled, encryption, CloudWatch logs integration, and multi-region enabled"
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Audit Logging Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking audit logging: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkTimestreamAuditLogging(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Audit Logging is Enabled for Amazon Timestream",
	description:
		"Enable AWS CloudTrail to capture and log API calls and activities related to Amazon Timestream. Configure CloudTrail to store the logs in a secure location and regularly review the logs for any unauthorized or suspicious activities.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_10.6",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkTimestreamAuditLogging,
	serviceName: "Amazon Timestream for LiveAnalytics",
	shortServiceName: "timestream"
} satisfies RuntimeTest;
