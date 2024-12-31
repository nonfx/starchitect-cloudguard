import { IAMClient, ListUsersCommand, ListAccessKeysCommand } from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const MAX_KEY_AGE_DAYS = 90; // Maximum allowed age for access keys

async function checkAccessKeyRotation(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all IAM users
		const usersResponse = await client.send(new ListUsersCommand({}));

		if (!usersResponse.Users || usersResponse.Users.length === 0) {
			results.checks = [
				{
					resourceName: "No IAM Users",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No IAM users found"
				}
			];
			return results;
		}

		// Check access keys for each user
		for (const user of usersResponse.Users) {
			if (!user.UserName) continue;

			try {
				const accessKeysResponse = await client.send(
					new ListAccessKeysCommand({
						UserName: user.UserName
					})
				);

				if (
					!accessKeysResponse.AccessKeyMetadata ||
					accessKeysResponse.AccessKeyMetadata.length === 0
				) {
					results.checks.push({
						resourceName: user.UserName,
						resourceArn: user.Arn,
						status: ComplianceStatus.PASS,
						message: "User has no access keys"
					});
					continue;
				}

				// Check each access key's age
				for (const key of accessKeysResponse.AccessKeyMetadata) {
					if (!key.CreateDate) continue;

					const keyAge = Math.floor(
						(new Date().getTime() - key.CreateDate.getTime()) / (1000 * 60 * 60 * 24)
					);

					results.checks.push({
						resourceName: `${user.UserName} (${key.AccessKeyId})`,
						resourceArn: user.Arn,
						status: keyAge <= MAX_KEY_AGE_DAYS ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message:
							keyAge <= MAX_KEY_AGE_DAYS
								? undefined
								: `Access key is ${keyAge} days old (maximum allowed is ${MAX_KEY_AGE_DAYS} days)`
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: user.UserName,
					resourceArn: user.Arn,
					status: ComplianceStatus.ERROR,
					message: `Error checking access keys: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "IAM Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking IAM users: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAccessKeyRotation(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Access Keys are Regularly Rotated",
	description:
		"Regularly rotating your Aurora Access Keys is critical to access management, contributing to maintaining system security",
	severity: "HIGH",
	controls: [],
	execute: checkAccessKeyRotation,
	serviceName: "Amazon Relational Database Service",
	shortServiceName: "rds"
} satisfies RuntimeTest;
