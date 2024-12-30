import {
	CloudTrailClient,
	DescribeTrailsCommand,
	GetTrailStatusCommand
} from "@aws-sdk/client-cloudtrail";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { type ComplianceReport, ComplianceStatus, type RuntimeTest } from "../../types.js";

async function checkCloudTrailEnabled(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new CloudTrailClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all CloudTrail trails
		const response = await client.send(new DescribeTrailsCommand({}));

		if (!response.trailList || response.trailList.length === 0) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.FAIL,
				message: "No CloudTrail trails found in the account"
			});
			return results;
		}

		// Check if at least one trail is enabled
		let enabledTrailFound = false;

		for (const trail of response.trailList) {
			if (!trail.Name || !trail.TrailARN) {
				results.checks.push({
					resourceName: "Unknown Trail",
					status: ComplianceStatus.ERROR,
					message: "Trail found without name or ARN"
				});
				continue;
			}

			// Get trail status
			const statusCommand = new GetTrailStatusCommand({ Name: trail.Name });
			const statusResponse = await client.send(statusCommand);

			if (trail.IsMultiRegionTrail && statusResponse.IsLogging) {
				enabledTrailFound = true;
				results.checks.push({
					resourceName: trail.Name,
					resourceArn: trail.TrailARN,
					status: ComplianceStatus.PASS
				});
			} else {
				results.checks.push({
					resourceName: trail.Name,
					resourceArn: trail.TrailARN,
					status: ComplianceStatus.FAIL,
					message: statusResponse.IsLogging
						? "Trail is not multi-region"
						: "Trail logging is not enabled"
				});
			}
		}

		if (!enabledTrailFound) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.FAIL,
				message: "No enabled multi-region CloudTrail trails found"
			});
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
	const results = await checkCloudTrailEnabled(region);
	printSummary(generateSummary(results));
}

export default {
	title: "At least one CloudTrail trail should be enabled",
	description:
		"This control checks whether an AWS CloudTrail trail is enabled in your AWS account. The control fails if your account doesn't have at least one CloudTrail trail enabled.However, some AWS services do not enable logging of all APIs and events. You should implement any additional audit trails other than CloudTrail and review the documentation for each service in CloudTrail Supported Services and Integrations",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkCloudTrailEnabled,
	serviceName: "AWS CloudTrail"
} satisfies RuntimeTest;
