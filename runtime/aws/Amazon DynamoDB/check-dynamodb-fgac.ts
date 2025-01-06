import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { IAMClient, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { getAllIAMPolicies } from "../Amazon Identity and Access Management/get-all-iam-policies.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllDynamoDBTables } from "./get-all-dynamodb-tables.js";

interface PolicyDocument {
	Version: string;
	Statement: Array<{
		Effect: string;
		Action: string | string[];
		Resource: string | string[];
	}>;
}

function hasWildcardAccess(policyDoc: PolicyDocument): boolean {
	return policyDoc.Statement.some(statement => {
		if (statement.Effect !== "Allow") return false;

		const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
		return actions.some(action => action === "*" || action === "dynamodb:*");
	});
}

async function checkDynamoDBFGACCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const dynamoClient = new DynamoDBClient({ region });
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = { checks: [] };

	try {
		// First check if there are any DynamoDB tables using pagination
		const tableNames = await getAllDynamoDBTables(dynamoClient);

		if (tableNames.length === 0) {
			results.checks.push({
				resourceName: "DynamoDB Tables",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No DynamoDB tables found"
			});
			return results;
		}

		// Get all IAM policies
		const policies = await getAllIAMPolicies(iamClient);

		if (policies.length === 0) {
			results.checks.push({
				resourceName: "IAM Policies",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No IAM policies found"
			});
			return results;
		}

		// Check each policy
		for (const policy of policies) {
			if (!policy.Arn || !policy.DefaultVersionId) continue;

			try {
				const versionResponse = await iamClient.send(
					new GetPolicyVersionCommand({
						PolicyArn: policy.Arn,
						VersionId: policy.DefaultVersionId
					})
				);

				if (!versionResponse.PolicyVersion?.Document) continue;

				const policyDoc = JSON.parse(
					decodeURIComponent(versionResponse.PolicyVersion.Document)
				) as PolicyDocument;
				const hasBroadAccess = hasWildcardAccess(policyDoc);

				results.checks.push({
					resourceName: policy.PolicyName || "Unknown Policy",
					resourceArn: policy.Arn,
					status: hasBroadAccess ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasBroadAccess ? "Policy contains overly permissive DynamoDB access" : undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: policy.PolicyName || "Unknown Policy",
					resourceArn: policy.Arn,
					status: ComplianceStatus.ERROR,
					message: `Error checking policy: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "DynamoDB FGAC Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking DynamoDB FGAC: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDynamoDBFGACCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon DynamoDB",
	shortServiceName: "dynamodb",
	title: "Ensure Fine-Grained Access Control is implemented",
	description:
		"Fine-Grained Access Control (FGAC) on Amazon DynamoDB allows you to control access to data at the row level. Using IAM policies, you can restrict access based on the content within the request.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_4.2",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkDynamoDBFGACCompliance
} satisfies RuntimeTest;
