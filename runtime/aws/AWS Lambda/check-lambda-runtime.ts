import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// List of supported runtimes
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

async function checkLambdaRuntimeCompliance(
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

					// Skip check for Image-based functions
					if (funcDetails.Configuration?.PackageType === "Image") {
						results.checks.push({
							resourceName: func.FunctionName,
							resourceArn: func.FunctionArn,
							status: ComplianceStatus.PASS,
							message: "Function uses container image packaging"
						});
						continue;
					}

					const runtime = funcDetails.Configuration?.Runtime;
					const isSupported = runtime && SUPPORTED_RUNTIMES.includes(runtime);

					results.checks.push({
						resourceName: func.FunctionName,
						resourceArn: func.FunctionArn,
						status: isSupported ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: isSupported
							? undefined
							: `Function uses unsupported runtime '${runtime}'. Use one of the supported runtimes: ${SUPPORTED_RUNTIMES.join(", ")}`
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
	const results = await checkLambdaRuntimeCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "Lambda functions should use supported runtimes",
	description:
		"This control checks if Lambda functions use supported runtimes. Functions with unsupported or deprecated runtimes may pose security risks due to lack of updates.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Lambda.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkLambdaRuntimeCompliance
} satisfies RuntimeTest;
