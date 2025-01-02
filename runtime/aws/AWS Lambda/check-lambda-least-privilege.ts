import {
	IAMClient,
	ListAttachedRolePoliciesCommand,
	GetPolicyVersionCommand
} from "@aws-sdk/client-iam";
import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";

interface PolicyStatement {
	Effect: string;
	Action: string | string[];
	Resource: string | string[];
}

interface PolicyDocument {
	Version: string;
	Statement: PolicyStatement[];
}

function hasOverlyPermissiveActions(policyDoc: PolicyDocument): boolean {
	console.log(policyDoc);
	return policyDoc.Statement.some(statement => {
		if (statement.Effect !== "Allow") return false;
		const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
		return actions.some(action => action.includes("*"));
	});
}

async function checkLambdaLeastPrivilegeCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const lambdaClient = new LambdaClient({ region });
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Lambda functions
		const functions = await lambdaClient.send(new ListFunctionsCommand({}));

		if (!functions.Functions || functions.Functions.length === 0) {
			results.checks = [
				{
					resourceName: "No Lambda Functions",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Lambda functions found in the region"
				}
			];
			return results;
		}

		for (const func of functions.Functions) {
			if (!func.FunctionName || !func.Role) {
				results.checks.push({
					resourceName: func.FunctionName || "Unknown Function",
					status: ComplianceStatus.ERROR,
					message: "Function missing name or role ARN"
				});
				continue;
			}

			try {
				// Get role policies
				const roleName = func.Role.split("/").pop();
				if (!roleName) {
					throw new Error("Invalid role ARN format");
				}

				// Check inline policies
				const inlinePolicies = await iamClient.send(
					new ListAttachedRolePoliciesCommand({
						RoleName: roleName
					})
				);

				let hasOverlyPermissive = false;

				// Check each attached policy
				if (inlinePolicies.AttachedPolicies) {
					for (const policy of inlinePolicies.AttachedPolicies) {
						if (!policy.PolicyArn) continue;

						const policyVersion = await iamClient.send(
							new GetPolicyVersionCommand({
								PolicyArn: policy.PolicyArn,
								VersionId: "v1"
							})
						);

						if (policyVersion.PolicyVersion?.Document) {
							const policyDoc = JSON.parse(
								decodeURIComponent(policyVersion.PolicyVersion.Document)
							);
							if (hasOverlyPermissiveActions(policyDoc)) {
								hasOverlyPermissive = true;
								break;
							}
						}
					}
				}

				results.checks.push({
					resourceName: func.FunctionName,
					resourceArn: func.FunctionArn,
					status: hasOverlyPermissive ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasOverlyPermissive
						? "Lambda function has overly permissive IAM policies"
						: undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: func.FunctionName,
					resourceArn: func.FunctionArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking function policies: ${error instanceof Error ? error.message : String(error)}`
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
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "";
	const results = await checkLambdaLeastPrivilegeCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Lambda",
	shortServiceName: "lambda",
	title: "Ensure least privilege is used with Lambda function access",
	description:
		"Lambda is fully integrated with IAM, allowing you to control precisely what each Lambda function can do within the AWS Cloud. As you develop a Lambda function, you expand the scope of this policy to enable access to other resources. For example, for a function that processes objects put into an S3 bucket, it requires read access to objects stored in that bucket. Do not grant the function broader permissions to write or delete data, or operate in other buckets.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.4",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkLambdaLeastPrivilegeCompliance
} satisfies RuntimeTest;
