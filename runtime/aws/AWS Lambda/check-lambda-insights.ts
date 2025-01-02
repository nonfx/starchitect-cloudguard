import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkLambdaInsightsCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new LambdaClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextMarker: string | undefined;
		let functionsFound = false;

		do {
			const listCommand = new ListFunctionsCommand({
				Marker: nextMarker
			});

			const response = await client.send(listCommand);

			if (!response.Functions || response.Functions.length === 0) {
				if (!functionsFound) {
					results.checks = [
						{
							resourceName: "No Lambda Functions",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No Lambda functions found in the region"
						}
					];
					return results;
				}
				break;
			}

			functionsFound = true;

			for (const func of response.Functions) {
				if (!func.FunctionName || !func.FunctionArn) {
					results.checks.push({
						resourceName: "Unknown Function",
						status: ComplianceStatus.ERROR,
						message: "Function found without name or ARN"
					});
					continue;
				}

				try {
					const getCommand = new GetFunctionCommand({
						FunctionName: func.FunctionName
					});

					const funcDetails = await client.send(getCommand);
					const layers = funcDetails.Configuration?.Layers || [];

					const hasInsights = layers.some(layer =>
						layer.Arn?.includes(":layer:LambdaInsightsExtension:")
					);

					results.checks.push({
						resourceName: func.FunctionName,
						resourceArn: func.FunctionArn,
						status: hasInsights ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: hasInsights
							? undefined
							: "Lambda function does not have CloudWatch Lambda Insights enabled"
					});
				} catch (error) {
					results.checks.push({
						resourceName: func.FunctionName,
						resourceArn: func.FunctionArn,
						status: ComplianceStatus.ERROR,
						message: `Error checking function details: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}

			nextMarker = response.NextMarker;
		} while (nextMarker);
	} catch (error) {
		results.checks = [
			{
				resourceName: "Lambda Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Lambda functions: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkLambdaInsightsCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "Ensure Cloudwatch Lambda insights is enabled",
	description:
		"Ensure that Amazon CloudWatch Lambda Insights is enabled for your Amazon Lambda functions for enhanced monitoring",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.2",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkLambdaInsightsCompliance
} satisfies RuntimeTest;
