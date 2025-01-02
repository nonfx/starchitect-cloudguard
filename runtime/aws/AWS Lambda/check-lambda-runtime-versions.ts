import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const SUPPORTED_RUNTIMES = [
	"nodejs22.x",
	"nodejs20.x",
	"nodejs18.x",
	"python3.13",
	"python3.12",
	"python3.11",
	"python3.10",
	"python3.9",
	"python3.8",
	"java21",
	"java17",
	"java11",
	"java8.al2",
	"dotnet8",
	"dotnet6",
	"ruby3.4",
	"ruby3.3",
	"ruby3.2",
	"provided.al2023",
	"provided.al2"
];

async function checkLambdaRuntimeVersions(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new LambdaClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextMarker: string | undefined;
		let functionsFound = false;

		do {
			const command = new ListFunctionsCommand({
				Marker: nextMarker
			});

			const response = await client.send(command);

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
				if (!func.FunctionName || !func.Runtime) {
					results.checks.push({
						resourceName: func.FunctionName || "Unknown Function",
						status: ComplianceStatus.ERROR,
						message: "Function missing name or runtime information"
					});
					continue;
				}

				const isSupported = SUPPORTED_RUNTIMES.includes(func.Runtime);

				results.checks.push({
					resourceName: func.FunctionName,
					resourceArn: func.FunctionArn,
					status: isSupported ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isSupported ? undefined : `Function uses unsupported runtime: ${func.Runtime}`
				});
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
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkLambdaRuntimeVersions(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title:
		"Ensure that the runtime environment versions used for your Lambda functions do not have end of support dates",
	description:
		"Always using a recent version of the execution environment configured for your Amazon Lambda functions adheres to best practices for the newest software features, the latest security patches and bug fixes, and performance and reliability",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.11",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkLambdaRuntimeVersions
} satisfies RuntimeTest;
