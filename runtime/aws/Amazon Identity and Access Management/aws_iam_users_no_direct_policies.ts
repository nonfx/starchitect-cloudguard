import {
	IAMClient,
	ListUsersCommand,
	ListAttachedUserPoliciesCommand,
	ListUserPoliciesCommand
} from "@aws-sdk/client-iam";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkIamUserPolicies(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all IAM users
		const usersResponse = await client.send(new ListUsersCommand({}));

		if (!usersResponse.Users || usersResponse.Users.length === 0) {
			results.checks.push({
				resourceName: "No IAM Users",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No IAM users found"
			});
			return results;
		}

		for (const user of usersResponse.Users) {
			if (!user.UserName || !user.Arn) {
				results.checks.push({
					resourceName: "Unknown User",
					status: ComplianceStatus.ERROR,
					message: "User found without name or ARN"
				});
				continue;
			}

			try {
				// Check attached policies
				const attachedPoliciesResponse = await client.send(
					new ListAttachedUserPoliciesCommand({
						UserName: user.UserName
					})
				);

				// Check inline policies
				const inlinePoliciesResponse = await client.send(
					new ListUserPoliciesCommand({
						UserName: user.UserName
					})
				);

				const hasAttachedPolicies =
					attachedPoliciesResponse.AttachedPolicies &&
					attachedPoliciesResponse.AttachedPolicies.length > 0;
				const hasInlinePolicies =
					inlinePoliciesResponse.PolicyNames && inlinePoliciesResponse.PolicyNames.length > 0;

				if (hasAttachedPolicies || hasInlinePolicies) {
					results.checks.push({
						resourceName: user.UserName,
						resourceArn: user.Arn,
						status: ComplianceStatus.FAIL,
						message: `User has ${hasAttachedPolicies ? "attached" : ""} ${hasAttachedPolicies && hasInlinePolicies ? "and" : ""} ${hasInlinePolicies ? "inline" : ""} policies. Policies should be attached to groups instead.`
					});
				} else {
					results.checks.push({
						resourceName: user.UserName,
						resourceArn: user.Arn,
						status: ComplianceStatus.PASS
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: user.UserName,
					resourceArn: user.Arn,
					status: ComplianceStatus.ERROR,
					message: `Error checking user policies: ${error instanceof Error ? error.message : String(error)}`
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
	const results = await checkIamUserPolicies(region);
	printSummary(generateSummary(results));
}

export default {
	title: "IAM users should not have IAM policies attached",
	description:
		"IAM users should not have direct policy attachments; instead, policies should be attached to groups or roles to reduce access management complexity and minimize the risk of excessive privileges.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_IAM.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkIamUserPolicies,
	serviceName: "Amazon Identity and Access Management",
	shortServiceName: "iam"
} satisfies RuntimeTest;
