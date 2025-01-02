import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface RoleUsage {
	functionNames: string[];
	roleArn: string;
}

async function checkLambdaUniqueIamRoles(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new LambdaClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const roleMap = new Map<string, RoleUsage>();
		let nextMarker: string | undefined;

		do {
			const command = new ListFunctionsCommand({
				Marker: nextMarker
			});

			const response = await client.send(command);

			if (!response.Functions || response.Functions.length === 0) {
				results.checks = [
					{
						resourceName: "No Lambda Functions",
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No Lambda functions found in the region"
					}
				];
				return results;
			}

			// Process each function
			for (const func of response.Functions) {
				if (!func.FunctionName || !func.Role) {
					results.checks.push({
						resourceName: func.FunctionName || "Unknown Function",
						status: ComplianceStatus.ERROR,
						message: "Function missing name or role ARN"
					});
					continue;
				}

				// Track role usage with version information
				const roleUsage = roleMap.get(func.Role) || { functionNames: [], roleArn: func.Role };
				const fullName = `${func.FunctionName}:${func.Version || "$LATEST"}`;
				roleUsage.functionNames.push(fullName);
				roleMap.set(func.Role, roleUsage);
			}

			nextMarker = response.NextMarker;
		} while (nextMarker);

		// Evaluate role uniqueness
		for (const [roleArn, usage] of roleMap.entries()) {
			if (usage.functionNames.length > 1) {
				// Role is shared between multiple functions
				for (const functionName of usage.functionNames) {
					results.checks.push({
						resourceName: functionName,
						resourceArn: roleArn,
						status: ComplianceStatus.FAIL,
						message: `IAM role ${roleArn} is shared with other functions/versions: ${usage.functionNames
							.filter(f => !f.startsWith(functionName))
							.join(", ")}`
					});
				}
			} else {
				// Role is unique to one function
				const functionName = usage.functionNames[0];
				if (functionName) {
					results.checks.push({
						resourceName: functionName,
						resourceArn: roleArn,
						status: ComplianceStatus.PASS
					});
				}
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
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkLambdaUniqueIamRoles(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "Ensure every Lambda function has its own IAM Role",
	description:
		"Every Lambda function should have a one to one IAM execution role and the roles should not be shared between functions.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.5",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkLambdaUniqueIamRoles
} satisfies RuntimeTest;
