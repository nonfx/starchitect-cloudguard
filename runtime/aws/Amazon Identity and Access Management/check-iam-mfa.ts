import {
	IAMClient,
	ListUsersCommand,
	GetLoginProfileCommand,
	ListMFADevicesCommand
} from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface IamUser {
	UserName: string;
	Arn: string;
	HasConsoleAccess: boolean;
	HasMFA: boolean;
}

async function checkUserMfaCompliance(client: IAMClient, userName: string): Promise<IamUser> {
	// Check if user has console access
	let hasConsoleAccess = false;
	try {
		await client.send(new GetLoginProfileCommand({ UserName: userName }));
		hasConsoleAccess = true;
	} catch (error: any) {
		if (error.name !== "NoSuchEntity") {
			throw error;
		}
	}

	// Check if user has MFA devices
	const mfaResponse = await client.send(new ListMFADevicesCommand({ UserName: userName }));
	const hasMFA = (mfaResponse.MFADevices?.length ?? 0) > 0;

	return {
		UserName: userName,
		Arn: `arn:aws:iam::*:user/${userName}`,
		HasConsoleAccess: hasConsoleAccess,
		HasMFA: hasMFA
	};
}

async function checkIamUsersMfaCompliance(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const response = await client.send(new ListUsersCommand({}));

		if (!response.Users || response.Users.length === 0) {
			results.checks = [
				{
					resourceName: "No IAM Users",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No IAM users found in the account"
				}
			];
			return results;
		}

		for (const user of response.Users) {
			if (!user.UserName) {
				results.checks.push({
					resourceName: "Unknown User",
					status: ComplianceStatus.ERROR,
					message: "User found without username"
				});
				continue;
			}

			try {
				const userDetails = await checkUserMfaCompliance(client, user.UserName);

				if (userDetails.HasConsoleAccess) {
					results.checks.push({
						resourceName: userDetails.UserName,
						resourceArn: userDetails.Arn,
						status: userDetails.HasMFA ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: userDetails.HasMFA
							? undefined
							: "User has console access but no MFA device configured"
					});
				} else {
					results.checks.push({
						resourceName: userDetails.UserName,
						resourceArn: userDetails.Arn,
						status: ComplianceStatus.PASS,
						message: "User does not have console access"
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: user.UserName,
					resourceArn: user.Arn,
					status: ComplianceStatus.ERROR,
					message: `Error checking user MFA status: ${error instanceof Error ? error.message : String(error)}`
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
	const results = await checkIamUsersMfaCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
	description:
		"Multi-Factor Authentication (MFA) adds an extra layer of authentication assurance beyond traditional credentials. With MFA enabled, when a user signs in to the AWS Console, they will be prompted for their user name and password as well as for an authentication code from their physical or virtual MFA token. It is recommended that MFA be enabled for all accounts that have a console password.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.5",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	execute: checkIamUsersMfaCompliance
} satisfies RuntimeTest;
