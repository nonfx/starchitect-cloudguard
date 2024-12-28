import {
	IAMClient,
	ListUsersCommand,
	ListUserPoliciesCommand,
	ListAttachedUserPoliciesCommand,
	ListGroupsForUserCommand
} from "@aws-sdk/client-iam";

import { printSummary, generateSummary } from "../../utils/string-utils.js";

import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkIamUserPermissionsThroughGroups(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all IAM users
		const listUsersResponse = await client.send(new ListUsersCommand({}));

		if (!listUsersResponse.Users || listUsersResponse.Users.length === 0) {
			results.checks.push({
				resourceName: "No IAM Users",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No IAM users found"
			});
			return results;
		}

		for (const user of listUsersResponse.Users) {
			if (!user.UserName || !user.Arn) {
				results.checks.push({
					resourceName: "Unknown User",
					status: ComplianceStatus.ERROR,
					message: "User found without name or ARN"
				});
				continue;
			}

			try {
				// Check for inline policies
				const inlinePoliciesResponse = await client.send(
					new ListUserPoliciesCommand({
						UserName: user.UserName
					})
				);

				// Check for attached policies
				const attachedPoliciesResponse = await client.send(
					new ListAttachedUserPoliciesCommand({
						UserName: user.UserName
					})
				);

				// Check for group memberships
				const groupsResponse = await client.send(
					new ListGroupsForUserCommand({
						UserName: user.UserName
					})
				);

				const hasInlinePolicies = (inlinePoliciesResponse.PolicyNames || []).length > 0;
				const hasAttachedPolicies = (attachedPoliciesResponse.AttachedPolicies || []).length > 0;
				const hasGroups = (groupsResponse.Groups || []).length > 0;

				const isCompliant = hasGroups && !hasInlinePolicies && !hasAttachedPolicies;

				let message: string | undefined;
				if (!isCompliant) {
					const reasons = [];
					if (!hasGroups) reasons.push("not member of any groups");
					if (hasInlinePolicies) reasons.push("has inline policies");
					if (hasAttachedPolicies) reasons.push("has directly attached policies");
					message = `User ${reasons.join(", ")}`;
				}

				results.checks.push({
					resourceName: user.UserName,
					resourceArn: user.Arn,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message
				});
			} catch (error) {
				results.checks.push({
					resourceName: user.UserName,
					resourceArn: user.Arn,
					status: ComplianceStatus.ERROR,
					message: `Error checking user policies: ${
						error instanceof Error ? error.message : String(error)
					}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "IAM Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking IAM users: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkIamUserPermissionsThroughGroups(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure IAM Users Receive Permissions Only Through Groups",
	description:
		"IAM users should be granted permissions only through groups. Directly attached policies or inline policies should be avoided.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.15",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkIamUserPermissionsThroughGroups
} satisfies RuntimeTest;
