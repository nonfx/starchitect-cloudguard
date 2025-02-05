import { IAMClient, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { getAllIAMPolicies } from "../../utils/aws/get-all-iam-policies.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

import { printSummary, generateSummary } from "../../utils/string-utils.js";

interface PolicyStatement {
	Effect: string;
	Action: string | string[];
	Resource: string | string[];
}

interface PolicyDocument {
	Version: string;
	Statement: PolicyStatement | PolicyStatement[];
}

function asArray<T>(value: T | T[]): T[] {
	return Array.isArray(value) ? value : [value];
}

function parsePolicyDocument(policyJson: string): PolicyDocument {
	try {
		return JSON.parse(policyJson);
	} catch (error) {
		throw new Error(`Invalid policy document: ${error}`);
	}
}

function isWildcardPolicy(policyDocument: PolicyDocument): boolean {
	const statements = asArray(policyDocument.Statement);

	return statements.some(statement => {
		if (statement.Effect !== "Allow") return false;

		const actions = asArray(statement.Action);
		const resources = asArray(statement.Resource);

		const hasFullActions = actions.some(
			action => action === "*" || action === "*:*" || action === "iam:*"
		);

		const hasFullResources = resources.some(
			resource => resource === "*" || resource === "arn:aws:iam::*:*"
		);

		return hasFullActions && hasFullResources;
	});
}

async function checkIamFullAdminPrivileges(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const policies = await getAllIAMPolicies(client);

		if (policies.length === 0) {
			results.checks = [
				{
					resourceName: "No IAM Policies",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No customer managed policies found"
				}
			];
			return results;
		}

		// Check each policy
		for (const policy of policies) {
			const policyName = policy.PolicyName || "Unknown Policy";

			if (!policy.Arn || !policy.DefaultVersionId) {
				results.checks.push({
					resourceName: policyName,
					status: ComplianceStatus.ERROR,
					message: "Policy missing ARN or version ID"
				});
				continue;
			}

			try {
				// Get policy version details
				const versionCommand = new GetPolicyVersionCommand({
					PolicyArn: policy.Arn,
					VersionId: policy.DefaultVersionId
				});

				const versionResponse = await client.send(versionCommand);

				if (!versionResponse.PolicyVersion?.Document) {
					results.checks.push({
						resourceName: policyName,
						resourceArn: policy.Arn,
						status: ComplianceStatus.ERROR,
						message: "Policy version document is empty"
					});
					continue;
				}

				try {
					const policyDocument = parsePolicyDocument(
						decodeURIComponent(versionResponse.PolicyVersion.Document)
					);

					const hasWildcardPermissions = isWildcardPolicy(policyDocument);

					results.checks.push({
						resourceName: policyName,
						resourceArn: policy.Arn,
						status: hasWildcardPermissions ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
						message: hasWildcardPermissions
							? "Policy contains full administrative privileges (* action with * resource)"
							: undefined
					});
				} catch (error) {
					results.checks.push({
						resourceName: policyName,
						resourceArn: policy.Arn,
						status: ComplianceStatus.ERROR,
						message: `Error parsing policy document: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: policyName,
					resourceArn: policy.Arn,
					status: ComplianceStatus.ERROR,
					message: `Error fetching policy version: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "IAM Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking IAM policies: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkIamFullAdminPrivileges(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure IAM policies that allow full *:* administrative privileges are not attached",
	description:
		"IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege -that is, granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.16",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkIamFullAdminPrivileges,
	serviceName: "Amazon Identity and Access Management",
	shortServiceName: "iam"
} satisfies RuntimeTest;
