import {
	ConfigServiceClient,
	DescribeConfigurationRecordersCommand,
	DescribeConfigurationRecorderStatusCommand,
	GetDiscoveredResourceCountsCommand
} from "@aws-sdk/client-config-service";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkConfigEnabledAllRegions(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ConfigServiceClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check configuration recorders
		const recordersCommand = new DescribeConfigurationRecordersCommand({});
		const recordersResponse = await client.send(recordersCommand);

		if (
			!recordersResponse.ConfigurationRecorders ||
			recordersResponse.ConfigurationRecorders.length === 0
		) {
			results.checks.push({
				resourceName: "AWS Config",
				status: ComplianceStatus.FAIL,
				message: "No configuration recorders found. AWS Config is not enabled."
			});
			return results;
		}

		// Check configuration recorder status
		const statusCommand = new DescribeConfigurationRecorderStatusCommand({});
		const statusResponse = await client.send(statusCommand);

		if (
			!statusResponse.ConfigurationRecordersStatus ||
			statusResponse.ConfigurationRecordersStatus.length === 0
		) {
			results.checks.push({
				resourceName: "AWS Config",
				status: ComplianceStatus.FAIL,
				message: "Configuration recorder status not found."
			});
			return results;
		}

		// Check each recorder
		for (const recorder of recordersResponse.ConfigurationRecorders) {
			const recorderName = recorder.name || "Unknown Recorder";
			const recorderStatus = statusResponse.ConfigurationRecordersStatus.find(
				status => status.name === recorder.name
			);

			// Check if recorder is recording all resource types
			const recordingAllResources = recorder.recordingGroup?.allSupported === true;

			// Check if recorder is recording global resources
			const recordingGlobalResources = recorder.recordingGroup?.includeGlobalResourceTypes === true;

			// Check if recorder is active
			const isRecorderActive = recorderStatus?.recording === true;

			if (recordingAllResources && recordingGlobalResources && isRecorderActive) {
				results.checks.push({
					resourceName: recorderName,
					status: ComplianceStatus.PASS,
					message: "Configuration recorder is properly configured and active"
				});
			} else {
				const issues = [];
				if (!recordingAllResources) issues.push("not recording all resource types");
				if (!recordingGlobalResources) issues.push("not recording global resources");
				if (!isRecorderActive) issues.push("recorder is not active");

				results.checks.push({
					resourceName: recorderName,
					status: ComplianceStatus.FAIL,
					message: `Configuration recorder issues: ${issues.join(", ")}`
				});
			}
		}

		// Check if resources are being recorded
		const resourceCountCommand = new GetDiscoveredResourceCountsCommand({});
		const resourceCountResponse = await client.send(resourceCountCommand);

		if (
			!resourceCountResponse.totalDiscoveredResources ||
			resourceCountResponse.totalDiscoveredResources === 0
		) {
			results.checks.push({
				resourceName: "AWS Config",
				status: ComplianceStatus.FAIL,
				message: "No resources are being recorded by AWS Config"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "AWS Config",
			status: ComplianceStatus.ERROR,
			message: `Error checking AWS Config: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkConfigEnabledAllRegions(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure AWS Config is enabled in all regions",
	description:
		"AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration item (AWS resource), relationships between configuration items (AWS resources), any configuration changes between resources. It is recommended AWS Config be enabled in all regions.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_3.3",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkConfigEnabledAllRegions,
	serviceName: "AWS Config",
	shortServiceName: "aws-config"
} satisfies RuntimeTest;
