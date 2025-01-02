import {
	IAMClient,
	ListAttachedRolePoliciesCommand,
	GetPolicyVersionCommand
} from "@aws-sdk/client-iam";
import { LambdaClient, ListFunctionsCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface PolicyDocument {
	Version: string;
	Statement: Array<{
		Effect: string;
		Action: string[] | string;
		Resource: string[] | string;
	}>;
}

function hasAdminAccess(policyDoc: PolicyDocument): boolean {
	return policyDoc.Statement.some(statement => {
		const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
		const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

		return (
			statement.Effect === "Allow" &&
			actions.some(action => action.includes("*")) &&
			resources.some(resource => resource === "*")
		);
	});
}

async function checkLambdaPrivileges(region: string = "us-east-1"): Promise<ComplianceReport> {
	const lambdaClient = new LambdaClient({ region });
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = { checks: [] };

	try {
		const functions = await lambdaClient.send(new ListFunctionsCommand({}));

		if (!functions.Functions?.length) {
			results.checks.push({
				resourceName: "Lambda Functions",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Lambda functions found"
			});
			return results;
		}

		for (const func of functions.Functions) {
			if (!func.FunctionName || !func.Role) continue;

			try {
				const roleArn = func.Role;
				const roleName = roleArn.split("/").pop();

				if (!roleName) {
					results.checks.push({
						resourceName: func.FunctionName,
						status: ComplianceStatus.ERROR,
						message: "Invalid role ARN format"
					});
					continue;
				}

				// Check inline policies
				const inlinePolicies = await iamClient.send(
					new ListAttachedRolePoliciesCommand({
						RoleName: roleName
					})
				);

				let hasOverlyPermissivePolicy = false;

				// Check attached policies
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
							if (hasAdminAccess(policyDoc)) {
								hasOverlyPermissivePolicy = true;
								break;
							}
						}
					}
				}

				results.checks.push({
					resourceName: func.FunctionName,
					resourceArn: func.FunctionArn,
					status: hasOverlyPermissivePolicy ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasOverlyPermissivePolicy
						? "Lambda function has administrative privileges"
						: "No wildcard permissions found, but please verify the granted permissions align with your function's specific use case"
				});
			} catch (error) {
				results.checks.push({
					resourceName: func.FunctionName,
					status: ComplianceStatus.ERROR,
					message: `Error checking function permissions: ${error instanceof Error ? error.message : String(error)}`
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
	const region = process.env.AWS_REGION || "";
	const results = await checkLambdaPrivileges(region);
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
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.9",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkLambdaPrivileges
} satisfies RuntimeTest;
