import {
	GetGroupPolicyCommand,
	GetRolePolicyCommand,
	GetUserPolicyCommand,
	IAMClient,
	ListGroupPoliciesCommand,
	ListGroupsCommand,
	ListRolePoliciesCommand,
	ListRolesCommand,
	ListUserPoliciesCommand,
	ListUsersCommand
} from "@aws-sdk/client-iam";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

interface PolicyDocument {
	Version: string;
	Statement: PolicyStatement[];
}

interface PolicyStatement {
	Effect: string;
	Action: string | string[];
	Resource: string | string[];
}

const KMS_DECRYPT_ACTIONS = ["kms:Decrypt", "kms:ReEncryptFrom"];

function hasDecryptAllKeysPermission(policyDoc: PolicyDocument): boolean {
	return policyDoc.Statement.some(statement => {
		const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
		const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

		return (
			statement.Effect === "Allow" &&
			actions.some(action => KMS_DECRYPT_ACTIONS.includes(action)) &&
			resources.includes("*")
		);
	});
}

async function checkInlinePolicyKmsDecrypt(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check Users
		const users = await client.send(new ListUsersCommand({}));
		for (const user of users.Users || []) {
			if (!user.UserName) continue;

			const userPolicies = await client.send(
				new ListUserPoliciesCommand({
					UserName: user.UserName
				})
			);

			for (const policyName of userPolicies.PolicyNames || []) {
				try {
					const policy = await client.send(
						new GetUserPolicyCommand({
							UserName: user.UserName,
							PolicyName: policyName
						})
					);

					if (policy.PolicyDocument) {
						const policyDoc = JSON.parse(decodeURIComponent(policy.PolicyDocument));
						const hasViolation = hasDecryptAllKeysPermission(policyDoc);

						results.checks.push({
							resourceName: `User:${user.UserName}/Policy:${policyName}`,
							resourceArn: user.Arn,
							status: hasViolation ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
							message: hasViolation
								? "Inline policy allows KMS decrypt actions on all keys"
								: undefined
						});
					}
				} catch (error) {
					results.checks.push({
						resourceName: `User:${user.UserName}/Policy:${policyName}`,
						status: ComplianceStatus.ERROR,
						message: `Error checking policy: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}
		}

		// Check Roles
		const roles = await client.send(new ListRolesCommand({}));
		for (const role of roles.Roles || []) {
			if (!role.RoleName) continue;

			const rolePolicies = await client.send(
				new ListRolePoliciesCommand({
					RoleName: role.RoleName
				})
			);

			for (const policyName of rolePolicies.PolicyNames || []) {
				try {
					const policy = await client.send(
						new GetRolePolicyCommand({
							RoleName: role.RoleName,
							PolicyName: policyName
						})
					);

					if (policy.PolicyDocument) {
						const policyDoc = JSON.parse(decodeURIComponent(policy.PolicyDocument));
						const hasViolation = hasDecryptAllKeysPermission(policyDoc);

						results.checks.push({
							resourceName: `Role:${role.RoleName}/Policy:${policyName}`,
							resourceArn: role.Arn,
							status: hasViolation ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
							message: hasViolation
								? "Inline policy allows KMS decrypt actions on all keys"
								: undefined
						});
					}
				} catch (error) {
					results.checks.push({
						resourceName: `Role:${role.RoleName}/Policy:${policyName}`,
						status: ComplianceStatus.ERROR,
						message: `Error checking policy: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}
		}

		// Check Groups
		const groups = await client.send(new ListGroupsCommand({}));
		for (const group of groups.Groups || []) {
			if (!group.GroupName) continue;

			const groupPolicies = await client.send(
				new ListGroupPoliciesCommand({
					GroupName: group.GroupName
				})
			);

			for (const policyName of groupPolicies.PolicyNames || []) {
				try {
					const policy = await client.send(
						new GetGroupPolicyCommand({
							GroupName: group.GroupName,
							PolicyName: policyName
						})
					);

					if (policy.PolicyDocument) {
						const policyDoc = JSON.parse(decodeURIComponent(policy.PolicyDocument));
						const hasViolation = hasDecryptAllKeysPermission(policyDoc);

						results.checks.push({
							resourceName: `Group:${group.GroupName}/Policy:${policyName}`,
							resourceArn: group.Arn,
							status: hasViolation ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
							message: hasViolation
								? "Inline policy allows KMS decrypt actions on all keys"
								: undefined
						});
					}
				} catch (error) {
					results.checks.push({
						resourceName: `Group:${group.GroupName}/Policy:${policyName}`,
						status: ComplianceStatus.ERROR,
						message: `Error checking policy: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}
		}

		if (results.checks.length === 0) {
			results.checks.push({
				resourceName: "No IAM Principals",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No IAM principals with inline policies found"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "IAM Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking IAM policies: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkInlinePolicyKmsDecrypt(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys",
	description:
		"This control checks if IAM inline policies allow decryption actions on all KMS keys. Following least privilege principle, policies should restrict KMS actions to specific keys.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_KMS.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkInlinePolicyKmsDecrypt
} satisfies RuntimeTest;
