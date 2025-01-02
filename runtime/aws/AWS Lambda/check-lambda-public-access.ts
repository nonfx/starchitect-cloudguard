import { LambdaClient, GetPolicyCommand, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import type { FunctionConfiguration } from "@aws-sdk/client-lambda";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface PolicyDocument {
	Version: string;
	Statement: PolicyStatement[];
}

interface PolicyStatement {
	Effect: string;
	Principal: string | { [key: string]: string };
	Action: string | string[];
	Resource: string;
	Condition?: {
		StringEquals?: {
			["aws:SourceAccount"]?: string;
		};
	};
}

function isPublicPrincipal(principal: string | { [key: string]: string }): boolean {
	if (typeof principal === "string") {
		return principal === "*";
	}
	return principal["AWS"] === "*";
}

function hasValidS3Condition(statement: PolicyStatement): boolean {
	const principal =
		typeof statement.Principal === "string" ? statement.Principal : statement.Principal["Service"];

	return (
		principal === "s3.amazonaws.com" &&
		statement.Condition?.StringEquals?.["aws:SourceAccount"] !== undefined
	);
}

async function checkLambdaPublicAccessCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new LambdaClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Helper function to get all Lambda functions with pagination
		async function getAllFunctions() {
			const allFunctions: FunctionConfiguration[] = [];
			let marker: string | undefined;

			do {
				const response = await client.send(
					new ListFunctionsCommand({
						Marker: marker
					})
				);
				if (response.Functions) {
					allFunctions.push(...response.Functions);
				}
				marker = response.NextMarker;
			} while (marker);

			return allFunctions;
		}

		// Get all Lambda functions using pagination
		const allFunctions = await getAllFunctions();

		if (!allFunctions.length) {
			results.checks.push({
				resourceName: "No Lambda Functions",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Lambda functions found in the region"
			});
			return results;
		}

		for (const func of allFunctions) {
			if (!func.FunctionName) continue;

			try {
				const getPolicyCommand = new GetPolicyCommand({
					FunctionName: func.FunctionName
				});

				try {
					const policyResponse = await client.send(getPolicyCommand);

					if (policyResponse.Policy) {
						const policy: PolicyDocument = JSON.parse(policyResponse.Policy);
						let hasPublicAccess = false;

						for (const statement of policy.Statement) {
							if (isPublicPrincipal(statement.Principal) && !hasValidS3Condition(statement)) {
								hasPublicAccess = true;
								break;
							}
						}

						results.checks.push({
							resourceName: func.FunctionName,
							resourceArn: func.FunctionArn,
							status: hasPublicAccess ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
							message: hasPublicAccess
								? "Lambda function has public access permissions or missing AWS:SourceAccount condition for S3 invocations"
								: undefined
						});
					} else {
						results.checks.push({
							resourceName: func.FunctionName,
							resourceArn: func.FunctionArn,
							status: ComplianceStatus.PASS,
							message: "No resource policy attached"
						});
					}
				} catch (error: any) {
					if (error.name === "ResourceNotFoundException") {
						results.checks.push({
							resourceName: func.FunctionName,
							resourceArn: func.FunctionArn,
							status: ComplianceStatus.PASS,
							message: "No resource policy attached"
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
		results.checks.push({
			resourceName: "Lambda Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Lambda functions: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkLambdaPublicAccessCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "Lambda function policies should prohibit public access",
	description:
		"This control checks if Lambda function's resource-based policy prohibits public access and implements proper AWS:SourceAccount conditions for S3 invocations.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Lambda.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "CRITICAL",
	execute: checkLambdaPublicAccessCompliance
} satisfies RuntimeTest;
