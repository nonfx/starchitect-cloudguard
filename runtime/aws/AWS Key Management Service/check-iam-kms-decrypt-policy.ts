import { GetPolicyVersionCommand, IAMClient, ListPoliciesCommand } from "@aws-sdk/client-iam";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

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

function hasUnrestrictedKmsDecrypt(policyDocument: PolicyDocument): boolean {
	const kmsDecryptActions = ["kms:Decrypt", "kms:ReEncryptFrom"];
	const statements = asArray(policyDocument.Statement);

	return statements.some(statement => {
		if (statement.Effect !== "Allow") return false;

		const actions = asArray(statement.Action);
		const resources = asArray(statement.Resource);

		// Check if any KMS decrypt actions are allowed
		const hasDecryptAction = actions.some(
			action => kmsDecryptActions.includes(action) || action === "kms:*" || action === "*"
		);

		// Check if resources include all KMS keys
		const hasAllKmsResources = resources.some(
			resource =>
				resource === "*" ||
				(typeof resource === "string" &&
					resource.startsWith("arn:aws:kms:") &&
					resource.endsWith("*"))
		);

		return hasDecryptAction && hasAllKmsResources;
	});
}

async function checkIamKmsDecryptPolicy(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let marker: string | undefined;
		let policyFound = false;

		do {
			try {
				const listCommand = new ListPoliciesCommand({
					Marker: marker,
					Scope: "Local", // Only check customer managed policies
					OnlyAttached: true
				});

				const response = await client.send(listCommand);

				if (!response.Policies || response.Policies.length === 0) {
					if (!policyFound) {
						results.checks = [
							{
								resourceName: "No IAM Policies",
								status: ComplianceStatus.NOTAPPLICABLE,
								message: "No customer managed policies found"
							}
						];
						return results;
					}
					break;
				}

				for (const policy of response.Policies) {
					policyFound = true;
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

							const hasUnrestrictedDecrypt = hasUnrestrictedKmsDecrypt(policyDocument);

							results.checks.push({
								resourceName: policyName,
								resourceArn: policy.Arn,
								status: hasUnrestrictedDecrypt ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
								message: hasUnrestrictedDecrypt
									? "Policy allows KMS decryption actions on all keys"
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

				marker = response.Marker;
			} catch (error) {
				results.checks.push({
					resourceName: "Policy List",
					status: ComplianceStatus.ERROR,
					message: `Error listing policies: ${error instanceof Error ? error.message : String(error)}`
				});
				break;
			}
		} while (marker);
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
	const results = await checkIamKmsDecryptPolicy(region);
	printSummary(generateSummary(results));
}

export default {
	title: "IAM customer managed policies should not allow decryption actions on all KMS keys",
	description:
		"This control checks if IAM customer managed policies allow decryption actions (kms:Decrypt or kms:ReEncryptFrom) on all KMS keys. Following least privilege principles, policies should restrict these actions to specific keys.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_KMS.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkIamKmsDecryptPolicy
} satisfies RuntimeTest;
