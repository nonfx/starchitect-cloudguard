import { LambdaClient, GetPolicyCommand, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import type { FunctionConfiguration } from "@aws-sdk/client-lambda";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface PolicyDocument {
	Statement: Array<{
		Effect: string;
		Principal: string | { [key: string]: string | string[] };
		Action: string | string[];
		Resource: string;
	}>;
}

async function checkLambdaExposure(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new LambdaClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Helper function to get all Lambda functions with pagination
		async function getAllFunctions() {
			const allFunctions: FunctionConfiguration[] = [];
			let nextMarker: string | undefined;

			do {
				const response = await client.send(
					new ListFunctionsCommand({
						Marker: nextMarker
					})
				);
				if (response.Functions) {
					allFunctions.push(...response.Functions);
				}
				nextMarker = response.NextMarker;
			} while (nextMarker);

			return allFunctions;
		}

		// Get all Lambda functions using pagination
		const allFunctions = await getAllFunctions();

		if (allFunctions.length === 0) {
			results.checks = [
				{
					resourceName: "No Lambda Functions",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Lambda functions found in the region"
				}
			];
			return results;
		}

		for (const func of allFunctions) {
			if (!func.FunctionName || !func.FunctionArn) {
				results.checks.push({
					resourceName: "Unknown Function",
					status: ComplianceStatus.ERROR,
					message: "Function found without name or ARN"
				});
				continue;
			}

			try {
				// Get function policy
				const policyCommand = new GetPolicyCommand({
					FunctionName: func.FunctionName
				});

				try {
					const policyResponse = await client.send(policyCommand);
					if (policyResponse.Policy) {
						const policy: PolicyDocument = JSON.parse(policyResponse.Policy);
						const isPublic = policy.Statement.some(statement => {
							const principal =
								typeof statement.Principal === "string"
									? statement.Principal
									: statement.Principal["AWS"] || statement.Principal["*"];
							return (
								statement.Effect === "Allow" &&
								(principal === "*" || (Array.isArray(principal) && principal.includes("*")))
							);
						});

						results.checks.push({
							resourceName: func.FunctionName,
							resourceArn: func.FunctionArn,
							status: isPublic ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
							message: isPublic ? "Lambda function is publicly accessible" : undefined
						});
					} else {
						// No policy means no public access
						results.checks.push({
							resourceName: func.FunctionName,
							resourceArn: func.FunctionArn,
							status: ComplianceStatus.PASS,
							message: undefined
						});
					}
				} catch (error: any) {
					if (error.name === "ResourceNotFoundException") {
						// No policy means no public access
						results.checks.push({
							resourceName: func.FunctionName,
							resourceArn: func.FunctionArn,
							status: ComplianceStatus.PASS,
							message: undefined
						});
					} else {
						throw error;
					}
				}
			} catch (error) {
				results.checks.push({
					resourceName: func.FunctionName,
					resourceArn: func.FunctionArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking function policy: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
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
	const region = process.env.AWS_REGION || "";
	const results = await checkLambdaExposure(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "Ensure Lambda functions are not exposed to everyone",
	description:
		"A publicly accessible Amazon Lambda function is open to the public and can be reviewed by anyone. To protect against unauthorized users that are sending requests to invoke these functions they need to be changed so they are not exposed to the public.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.6",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkLambdaExposure
} satisfies RuntimeTest;
