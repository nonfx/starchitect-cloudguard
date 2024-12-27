import {
	IAMClient,
	ListUsersCommand,
	GetLoginProfileCommand,
	ListAccessKeysCommand
} from "@aws-sdk/client-iam";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkInitialAccessKeys(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const users = await client.send(new ListUsersCommand({}));

		if (!users.Users || users.Users.length === 0) {
			results.checks.push({
				resourceName: "No IAM Users",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No IAM users found"
			});
			return results;
		}

		for (const user of users.Users) {
			if (!user.UserName) continue;

			try {
				// Check if user has console access
				let hasConsoleAccess = false;
				try {
					await client.send(new GetLoginProfileCommand({ UserName: user.UserName }));
					hasConsoleAccess = true;
				} catch (error: any) {
					if (error.name !== "NoSuchEntity") {
						throw error;
					}
				}

				// If user has no console access, they're compliant by default
				if (!hasConsoleAccess) {
					results.checks.push({
						resourceName: user.UserName,
						resourceArn: user.Arn,
						status: ComplianceStatus.PASS,
						message: "User does not have console access"
					});
					continue;
				}

				// Check for access keys
				const accessKeys = await client.send(
					new ListAccessKeysCommand({ UserName: user.UserName })
				);
				const hasAccessKeys =
					accessKeys.AccessKeyMetadata && accessKeys.AccessKeyMetadata.length > 0;

				results.checks.push({
					resourceName: user.UserName,
					resourceArn: user.Arn,
					status: hasAccessKeys ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasAccessKeys ? "User has both console access and access keys" : undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: user.UserName,
					resourceArn: user.Arn,
					status: ComplianceStatus.ERROR,
					message: `Error checking user: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "IAM Users Check",
			status: ComplianceStatus.ERROR,
			message: `Error listing IAM users: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkInitialAccessKeys(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Do not setup access keys during initial user setup for all IAM users that have a console password",
	description:
		"AWS console defaults to no check boxes selected when creating a new IAM user. When creating the IAM User credentials you have to determine what type of access they require.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.11",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkInitialAccessKeys
} satisfies RuntimeTest;
