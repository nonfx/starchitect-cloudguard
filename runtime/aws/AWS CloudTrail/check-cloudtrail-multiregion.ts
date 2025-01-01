import {
	CloudTrailClient,
	GetTrailCommand,
	GetTrailStatusCommand,
	ListTrailsCommand
} from "@aws-sdk/client-cloudtrail";

import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkCloudTrailMultiRegionEnabled(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new CloudTrailClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get list of all trails
		const listResponse = await client.send(new ListTrailsCommand({}));

		if (!listResponse.Trails || listResponse.Trails.length === 0) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.FAIL,
				message: "No CloudTrail trails are configured"
			});
			return results;
		}

		let hasCompliantTrail = false;

		// Check each trail's configuration
		for (const trail of listResponse.Trails) {
			if (!trail.TrailARN || !trail.Name) {
				results.checks.push({
					resourceName: "Unknown Trail",
					status: ComplianceStatus.ERROR,
					message: "Trail found without name or ARN"
				});
				continue;
			}

			try {
				// Get detailed trail configuration
				const trailResponse = await client.send(new GetTrailCommand({ Name: trail.Name }));

				if (!trailResponse.Trail) {
					results.checks.push({
						resourceName: trail.Name,
						resourceArn: trail.TrailARN,
						status: ComplianceStatus.ERROR,
						message: "Unable to get trail configuration"
					});
					continue;
				}

				// Get trail status
				const statusCommand = new GetTrailStatusCommand({ Name: trail.Name });
				const statusResponse = await client.send(statusCommand);

				const isMultiRegion = trailResponse.Trail.IsMultiRegionTrail;
				const isLogging = statusResponse.IsLogging;
				const includesManagementEvents = trailResponse.Trail.IncludeGlobalServiceEvents;

				const isCompliant = isMultiRegion && isLogging && includesManagementEvents;

				if (isCompliant) {
					hasCompliantTrail = true;
				}

				results.checks.push({
					resourceName: trail.Name,
					resourceArn: trail.TrailARN,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: `Trail is not compliant: ${!isMultiRegion ? "not multi-region, " : ""}${!isLogging ? "not logging, " : ""}${!includesManagementEvents ? "management events not included" : ""}`
				});
			} catch (error) {
				results.checks.push({
					resourceName: trail.Name,
					resourceArn: trail.TrailARN,
					status: ComplianceStatus.ERROR,
					message: `Error checking trail configuration: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}

		// If no compliant trail was found, add a summary failure
		if (!hasCompliantTrail) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.FAIL,
				message: "No compliant multi-region trail with management events logging found"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "CloudTrail Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking CloudTrail configuration: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkCloudTrailMultiRegionEnabled(region);
	printSummary(generateSummary(results));
}

export default {
	title: "CloudTrail should be enabled and configured with at least one multi-Region trail",
	description:
		"CloudTrail must be enabled with multi-Region trail configuration capturing read/write management events for comprehensive AWS activity monitoring.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudTrailMultiRegionEnabled,
	serviceName: "AWS CloudTrail",
	shortServiceName: "cloudtrail"
} satisfies RuntimeTest;
