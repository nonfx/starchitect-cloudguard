import { IAMClient, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllIAMPolicies } from "../../utils/aws/get-all-iam-policies.js";

async function checkDynamoDBIAMAccessControl(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all IAM policies using pagination
		const policies = await getAllIAMPolicies(iamClient);
		let hasDynamoDBPolicy = false;

		// Check each policy for DynamoDB permissions
		for (const policy of policies) {
			if (!policy.Arn || !policy.DefaultVersionId) continue;

			const policyDetails = await iamClient.send(
				new GetPolicyVersionCommand({
					PolicyArn: policy.Arn,
					VersionId: policy.DefaultVersionId
				})
			);

			if (policyDetails.PolicyVersion?.Document) {
				const policyDoc =
					typeof policyDetails.PolicyVersion.Document === "string"
						? JSON.parse(decodeURIComponent(policyDetails.PolicyVersion.Document))
						: policyDetails.PolicyVersion.Document;

				let policyHasDynamoAction = false;
				const conditionTypes = new Set<string>();

				// Check each statement for DynamoDB actions
				for (const stmt of policyDoc.Statement || []) {
					// Handle undefined Action or non-string values
					if (!stmt.Action) continue;

					const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
					const hasDynamoAction = actions.some((action: unknown) => {
						if (typeof action !== "string") return false;
						return action.toLowerCase().includes("dynamodb:");
					});

					if (hasDynamoAction && stmt.Effect === "Allow") {
						hasDynamoDBPolicy = true;
						policyHasDynamoAction = true;
						if (stmt.Condition) {
							// Collect condition types for the message
							Object.keys(stmt.Condition).forEach(key => conditionTypes.add(key));
						}
					}
				}

				// Only add results for policies that have DynamoDB actions
				if (policyHasDynamoAction) {
					const conditionSuggestions = `Consider using these popular DynamoDB IAM policy conditions to enhance your security controls. Use dynamodb:LeadingKeys to restrict access based on partition key values, dynamodb:Attributes to limit access to specific item attributes, and dynamodb:RequestItems to control access in batch operations. For network-level security, aws:SourceIp can restrict access to specific IP ranges, while aws:UserAgent helps control access based on the client application making the request.`;

					results.checks.push({
						resourceName: policy.PolicyName || policy.Arn || "Unknown Policy",
						resourceArn: policy.Arn,
						status: conditionTypes.size > 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message:
							conditionTypes.size > 0
								? `Policy has DynamoDB conditions using: ${Array.from(conditionTypes).join(", ")}. Please verify these conditions match your security requirements.\n${conditionSuggestions}`
								: `Policy has DynamoDB permissions but no conditions. ${conditionSuggestions}`
					});
				}
			}
		}

		if (!hasDynamoDBPolicy) {
			results.checks.push({
				resourceName: "IAM Policies",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No IAM policies found with DynamoDB permissions"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "DynamoDB Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DynamoDB tables: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
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
