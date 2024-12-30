import {
	IAMClient,
	ListUsersCommand,
	GetAccessKeyLastUsedCommand,
	ListAccessKeysCommand,
	GetLoginProfileCommand
} from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface UserCredentialStatus {
	userName: string;
	passwordLastUsed?: Date;
	accessKeysLastUsed: Date[];
}

async function checkUserCredentials(
	client: IAMClient,
	userName: string
): Promise<UserCredentialStatus> {
	const status: UserCredentialStatus = {
		userName,
		accessKeysLastUsed: []
	};

	// Check password last used
	try {
		const loginProfile = await client.send(new GetLoginProfileCommand({ UserName: userName }));
		if (loginProfile.LoginProfile?.CreateDate) {
			status.passwordLastUsed = new Date(loginProfile.LoginProfile.CreateDate);
		}
	} catch (error: any) {
		if (error.name !== "NoSuchEntity") {
			throw error;
		}
	}

	// Check access keys last used
	const listKeysCommand = new ListAccessKeysCommand({ UserName: userName });
	const accessKeys = await client.send(listKeysCommand);

	if (accessKeys.AccessKeyMetadata) {
		for (const key of accessKeys.AccessKeyMetadata) {
			if (key.AccessKeyId) {
				const lastUsedCommand = new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId });
				const lastUsed = await client.send(lastUsedCommand);
				if (lastUsed.AccessKeyLastUsed?.LastUsedDate) {
					status.accessKeysLastUsed.push(new Date(lastUsed.AccessKeyLastUsed.LastUsedDate));
				}
			}
		}
	}

	return status;
}

function isCredentialCompliant(status: UserCredentialStatus): boolean {
	const now = new Date();
	const daysThreshold = 45;

	// Check password usage
	if (status.passwordLastUsed) {
		const daysSincePasswordUsed = Math.floor(
			(now.getTime() - status.passwordLastUsed.getTime()) / (1000 * 60 * 60 * 24)
		);
		if (daysSincePasswordUsed > daysThreshold) {
			return false;
		}
	}

	// Check access keys usage
	for (const lastUsed of status.accessKeysLastUsed) {
		const daysSinceKeyUsed = Math.floor(
			(now.getTime() - lastUsed.getTime()) / (1000 * 60 * 60 * 24)
		);
		if (daysSinceKeyUsed > daysThreshold) {
			return false;
		}
	}

	return true;
}

async function checkUnusedCredentials(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const listUsersCommand = new ListUsersCommand({});
		const users = await client.send(listUsersCommand);

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

		for (const user of users.Users) {
			if (!user.UserName) continue;

			try {
				const credentialStatus = await checkUserCredentials(client, user.UserName);
				const isCompliant = isCredentialCompliant(credentialStatus);

				results.checks.push({
					resourceName: user.UserName,
					resourceArn: user.Arn,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant ? undefined : "User has credentials unused for more than 45 days"
				});
			} catch (error) {
				results.checks.push({
					resourceName: user.UserName,
					resourceArn: user.Arn,
					status: ComplianceStatus.ERROR,
					message: `Error checking user credentials: ${error instanceof Error ? error.message : String(error)}`
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
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkUnusedCredentials(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure credentials unused for 45 days or greater are disabled",
	description:
		"AWS IAM users can access AWS resources using different types of credentials, such as passwords or access keys. It is recommended that all credentials that have been unused in 45 or greater days be deactivated or removed.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.12",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkUnusedCredentials
} satisfies RuntimeTest;
