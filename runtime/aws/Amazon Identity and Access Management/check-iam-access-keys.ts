import { IAMClient, ListAccessKeysCommand, ListUsersCommand } from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkIamUserAccessKeys(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all IAM users
		const users = await client.send(new ListUsersCommand({}));

		if (!users.Users || users.Users.length === 0) {
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
		for (const user of users.Users) {
			if (!user.UserName) {
				results.checks.push({
					resourceName: "Unknown User",
					status: ComplianceStatus.ERROR,
					message: "User found without username"
				});
				continue;
			}

			try {
				const accessKeys = await client.send(
					new ListAccessKeysCommand({
						UserName: user.UserName
					})
				);

				const activeKeys =
					accessKeys.AccessKeyMetadata?.filter(key => key.Status === "Active") || [];

				results.checks.push({
					resourceName: user.UserName,
					resourceArn: user.Arn,
					status: activeKeys.length <= 1 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message:
						activeKeys.length > 1
							? `User has ${activeKeys.length} active access keys. Only one should be active.`
							: undefined
				});
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

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkIamUserAccessKeys(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure there is only one active access key available for any single IAM user",
	description:
		"Access keys are long-term credentials for an IAM user or the AWS account root user. You can use access keys to sign programmatic requests to the AWS CLI or AWS API (directly or using the AWS SDK).",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.4",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkIamUserAccessKeys,
	serviceName: "Amazon Identity and Access Management",
	shortServiceName: "iam"
} satisfies RuntimeTest;
