import {
	ConfigServiceClient,
	DescribeConfigurationRecordersCommand,
	DescribeConfigurationRecorderStatusCommand
} from "@aws-sdk/client-config-service";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAwsConfigLambdaCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ConfigServiceClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get configuration recorders (returns all in one call)
		const recordersResponse = await client.send(new DescribeConfigurationRecordersCommand({}));
		const recorderStatusResponse = await client.send(
			new DescribeConfigurationRecorderStatusCommand({})
		);

		if (
			!recordersResponse.ConfigurationRecorders ||
			recordersResponse.ConfigurationRecorders.length === 0
		) {
			results.checks.push({
				resourceName: "AWS Config",
				status: ComplianceStatus.FAIL,
				message: "No AWS Config configuration recorders found"
			});
			return results;
		}

		for (const recorder of recordersResponse.ConfigurationRecorders) {
			const recorderName = recorder.name || "Unknown";
			const recorderStatus = recorderStatusResponse.ConfigurationRecordersStatus?.find(
				status => status.name === recorder.name
			);

			// Check if recorder is enabled
			const isEnabled = recorderStatus?.recording === true;

			// Check if Lambda resources are included based on recording strategy
			const recordingGroup = recorder.recordingGroup;
			const recordingStrategy = recordingGroup?.recordingStrategy?.useOnly;

			let lambdaIncluded = false;
			let isRecordingAllResources = false;

			if (recordingStrategy === "EXCLUSION_BY_RESOURCE_TYPES") {
				// In exclusion mode, all resources are recorded EXCEPT those in the exclusion list
				const excludedTypes = recordingGroup?.exclusionByResourceTypes?.resourceTypes || [];
				lambdaIncluded = !excludedTypes.includes("AWS::Lambda::Function");
				isRecordingAllResources = true;
			} else {
				// For ALL_SUPPORTED_RESOURCE_TYPES or INCLUSION_BY_RESOURCE_TYPES modes
				isRecordingAllResources =
					recordingGroup?.allSupported === true &&
					recordingGroup?.includeGlobalResourceTypes === true;
				lambdaIncluded =
					recordingGroup?.allSupported === true ||
					recordingGroup?.resourceTypes?.includes("AWS::Lambda::Function") ||
					false;
			}

			if (isEnabled && isRecordingAllResources && lambdaIncluded) {
				results.checks.push({
					resourceName: recorderName,
					status: ComplianceStatus.PASS,
					message: undefined
				});
			} else {
				let message = [];
				if (!isEnabled) message.push("Config recorder is not enabled");
				if (!isRecordingAllResources) message.push("Not recording all resources");
				if (!lambdaIncluded) message.push("Lambda resources are not included in recording");

				results.checks.push({
					resourceName: recorderName,
					status: ComplianceStatus.FAIL,
					message: message.join(", ")
				});
			}
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
	const region = process.env.AWS_REGION;
	const results = await checkAwsConfigLambdaCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "Ensure AWS Config is Enabled for Lambda and Serverless",
	description:
		"With AWS Config, you can track configuration changes to the Lambda functions (including deleted functions), runtime environments, tags, handler name, code size, memory allocation, timeout settings, and concurrency settings, along with Lambda IAM execution role, subnet, and security group associations",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.1",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAwsConfigLambdaCompliance
} satisfies RuntimeTest;
