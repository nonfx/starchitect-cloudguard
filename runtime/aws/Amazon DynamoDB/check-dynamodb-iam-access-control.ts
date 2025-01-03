import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
	IAMClient,
	ListRolesCommand,
	ListRolePoliciesCommand,
	GetRolePolicyCommand,
	ListAttachedRolePoliciesCommand,
	GetPolicyCommand,
	GetPolicyVersionCommand
} from "@aws-sdk/client-iam";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllDynamoDBTables } from "./get-all-dynamodb-tables.js";

interface PolicyStatement {
	Effect: string;
	Action: string | string[];
	Resource: string | string[];
}

interface PolicyDocument {
	Version: string;
	Statement: PolicyStatement[];
}

async function checkDynamoDBIAMAccessControl(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const dynamoClient = new DynamoDBClient({ region });
	const iamClient = new IAMClient({ region });
	const stsClient = new STSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get AWS account ID
		const identity = await stsClient.send(new GetCallerIdentityCommand({}));
		const accountId = identity.Account;
		if (!accountId) {
			throw new Error("Failed to get AWS account ID");
		}

		// Get all DynamoDB tables using pagination
		const tableNames = await getAllDynamoDBTables(dynamoClient);

		if (tableNames.length === 0) {
			results.checks = [
				{
					resourceName: "No DynamoDB Tables",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No DynamoDB tables found in the region"
				}
			];
			return results;
		}

		// Get all IAM roles
		const roles = await iamClient.send(new ListRolesCommand({}));
		if (!roles.Roles) {
			results.checks.push({
				resourceName: "IAM Roles",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No IAM roles found"
			});
			return results;
		}

		// Check each table
		for (const tableName of tableNames) {
			const tableArn = `arn:aws:dynamodb:${region}:${accountId}:table/${tableName}`;

			// Check each role
			for (const role of roles.Roles) {
				if (!role.RoleName) continue;

				try {
					// Check inline policies
					const inlinePolicies = await iamClient.send(
						new ListRolePoliciesCommand({ RoleName: role.RoleName })
					);

					for (const policyName of inlinePolicies.PolicyNames || []) {
						const policyDetails = await iamClient.send(
							new GetRolePolicyCommand({
								RoleName: role.RoleName,
								PolicyName: policyName
							})
						);

						if (policyDetails.PolicyDocument) {
							const policy = JSON.parse(
								decodeURIComponent(policyDetails.PolicyDocument)
							) as PolicyDocument;

							// Check if policy grants access to this table
							const hasTableAccess = policy.Statement.some(
								stmt =>
									stmt.Effect === "Allow" &&
									(Array.isArray(stmt.Resource)
										? stmt.Resource.includes(tableArn)
										: stmt.Resource === tableArn) &&
									(Array.isArray(stmt.Action)
										? stmt.Action.some(
												action => action === "dynamodb:*" || action.startsWith("dynamodb:")
											)
										: stmt.Action === "dynamodb:*" || stmt.Action.startsWith("dynamodb:"))
							);

							results.checks.push({
								resourceName: `${tableName} - Role:${role.RoleName} InlinePolicy:${policyName}`,
								resourceArn: tableArn,
								status: hasTableAccess ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
								message: hasTableAccess
									? `Inline policy ${policyName} grants appropriate access to table`
									: `Inline policy ${policyName} does not grant appropriate access to table`
							});
						}
					}

					// Check attached policies
					const attachedPolicies = await iamClient.send(
						new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName })
					);

					for (const policy of attachedPolicies.AttachedPolicies || []) {
						if (!policy.PolicyArn) continue;

						const policyDetails = await iamClient.send(
							new GetPolicyCommand({ PolicyArn: policy.PolicyArn })
						);

						if (policyDetails.Policy?.DefaultVersionId) {
							const versionDetails = await iamClient.send(
								new GetPolicyVersionCommand({
									PolicyArn: policy.PolicyArn,
									VersionId: policyDetails.Policy.DefaultVersionId
								})
							);

							if (versionDetails.PolicyVersion?.Document) {
								const policyDoc = JSON.parse(
									decodeURIComponent(versionDetails.PolicyVersion.Document)
								) as PolicyDocument;

								const hasTableAccess = policyDoc.Statement.some(
									stmt =>
										stmt.Effect === "Allow" &&
										(Array.isArray(stmt.Resource)
											? stmt.Resource.includes(tableArn)
											: stmt.Resource === tableArn) &&
										(Array.isArray(stmt.Action)
											? stmt.Action.some(
													action => action === "dynamodb:*" || action.startsWith("dynamodb:")
												)
											: stmt.Action === "dynamodb:*" || stmt.Action.startsWith("dynamodb:"))
								);

								results.checks.push({
									resourceName: `${tableName} - Role:${role.RoleName} ManagedPolicy:${policy.PolicyName}`,
									resourceArn: tableArn,
									status: hasTableAccess ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
									message: hasTableAccess
										? `Managed policy ${policy.PolicyName} grants appropriate access to table`
										: `Managed policy ${policy.PolicyName} does not grant appropriate access to table`
								});
							}
						}
					}
				} catch (error) {
					results.checks.push({
						resourceName: `${tableName} - Role:${role.RoleName}`,
						resourceArn: tableArn,
						status: ComplianceStatus.ERROR,
						message: `Error checking role policies: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "DynamoDB IAM Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DynamoDB IAM access controls: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkDynamoDBIAMAccessControl(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon DynamoDB",
	shortServiceName: "dynamodb",
	title:
		"AWS Identity and Access Management (IAM) lets you securely control your users' access to AWS services and resources. To manage access control for Amazon DynamoDB, you can create IAM policies that control access to tables and data",
	description:
		"This control checks if DynamoDB tables have appropriate IAM access controls configured through policies that restrict access to tables and data.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_4.1",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkDynamoDBIAMAccessControl
} satisfies RuntimeTest;
