import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import type { FunctionConfiguration } from "@aws-sdk/client-lambda";
import { IAMClient, GetRoleCommand } from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkLambdaExecutionRoles(region: string = "us-east-1"): Promise<ComplianceReport> {
	const lambdaClient = new LambdaClient({ region });
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Helper function to get all Lambda functions with pagination
		async function getAllFunctions() {
			const allFunctions: FunctionConfiguration[] = [];
			let nextMarker: string | undefined;

			do {
				const response = await lambdaClient.send(
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

		// Check each function's execution role
		for (const func of allFunctions) {
			if (!func.FunctionName || !func.Role) {
				results.checks.push({
					resourceName: func.FunctionName || "Unknown Function",
					status: ComplianceStatus.ERROR,
					message: "Function missing name or role ARN"
				});
				continue;
			}

			try {
				// Get function configuration to verify role
				const getFunctionResponse = await lambdaClient.send(
					new GetFunctionCommand({
						FunctionName: func.FunctionName
					})
				);

				const roleArn = getFunctionResponse.Configuration?.Role;
				if (!roleArn) {
					results.checks.push({
						resourceName: func.FunctionName,
						status: ComplianceStatus.FAIL,
						message: "Function does not have an execution role configured"
					});
					continue;
				}

				// Extract role name from ARN
				const roleName = roleArn.split("/").pop();
				if (!roleName) {
					results.checks.push({
						resourceName: func.FunctionName,
						status: ComplianceStatus.ERROR,
						message: "Invalid role ARN format"
					});
					continue;
				}

				try {
					// Verify if role exists and is active
					await iamClient.send(new GetRoleCommand({ RoleName: roleName }));

					results.checks.push({
						resourceName: func.FunctionName,
						resourceArn: func.FunctionArn,
						status: ComplianceStatus.PASS,
						message: undefined
					});
				} catch (error: any) {
					if (error.name === "NoSuchEntityException") {
						results.checks.push({
							resourceName: func.FunctionName,
							resourceArn: func.FunctionArn,
							status: ComplianceStatus.FAIL,
							message: "Function references a non-existent execution role"
						});
					} else {
						throw error;
					}
				}
			} catch (error) {
				results.checks.push({
					resourceName: func.FunctionName,
					status: ComplianceStatus.ERROR,
					message: `Error checking function configuration: ${error instanceof Error ? error.message : String(error)}`
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
	const region = process.env.AWS_REGION;
	const results = await checkLambdaExecutionRoles(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "Ensure Lambda functions are referencing active execution roles",
	description:
		"In order to have the necessary permissions to access the AWS cloud services and resources Amazon Lambda functions should be associated with active(available) execution roles.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.7",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkLambdaExecutionRoles
} satisfies RuntimeTest;
