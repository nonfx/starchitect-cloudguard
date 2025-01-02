import {
	LambdaClient,
	ListFunctionsCommand,
	GetFunctionCodeSigningConfigCommand
} from "@aws-sdk/client-lambda";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkLambdaCodeSigningCompliance(
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
					const getCommand = new GetFunctionCodeSigningConfigCommand({
						FunctionName: func.FunctionName
					});

					const funcDetails = await client.send(getCommand);
					const hasCodeSigning = !!funcDetails.CodeSigningConfigArn;

					results.checks.push({
						resourceName: func.FunctionName,
						resourceArn: func.FunctionArn,
						status: hasCodeSigning ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: hasCodeSigning
							? undefined
							: "Lambda function does not have Code Signing enabled"
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
	const results = await checkLambdaCodeSigningCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "Ensure that Code Signing is enabled for Lambda functions",
	description:
		"Ensure that all your Amazon Lambda functions are configured to use the Code Signing feature in order to restrict the deployment of unverified code.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.8",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkLambdaCodeSigningCompliance
} satisfies RuntimeTest;
