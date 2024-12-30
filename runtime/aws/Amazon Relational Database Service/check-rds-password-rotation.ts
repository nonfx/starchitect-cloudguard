import {
	IAMClient,
	ListUsersCommand,
	GetLoginProfileCommand,
	ListAccessKeysCommand
} from "@aws-sdk/client-iam";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const MAX_PASSWORD_AGE_DAYS = 90;
const MAX_ACCESS_KEY_AGE_DAYS = 90;

async function checkPasswordRotationCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const iamClient = new IAMClient({ region });
	const rdsClient = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check IAM Users
		const users = await iamClient.send(new ListUsersCommand({}));

		if (!users.Users || users.Users.length === 0) {
			results.checks.push({
				resourceName: "IAM Users",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No IAM users found"
			});
		} else {
			for (const user of users.Users) {
				if (!user.UserName) continue;

				// Check console access
				try {
					const loginProfile = await iamClient.send(
						new GetLoginProfileCommand({ UserName: user.UserName })
					);

					if (loginProfile.LoginProfile?.CreateDate) {
						const passwordAge = Math.floor(
							(Date.now() - loginProfile.LoginProfile.CreateDate.getTime()) / (1000 * 60 * 60 * 24)
						);

						results.checks.push({
							resourceName: `${user.UserName} (Console Password)`,
							resourceArn: user.Arn,
							status:
								passwordAge <= MAX_PASSWORD_AGE_DAYS
									? ComplianceStatus.PASS
									: ComplianceStatus.FAIL,
							message:
								passwordAge > MAX_PASSWORD_AGE_DAYS
									? `Password is ${passwordAge} days old (max: ${MAX_PASSWORD_AGE_DAYS})`
									: undefined
						});
					}
				} catch (error: any) {
					if (error.name !== "NoSuchEntity") {
						results.checks.push({
							resourceName: `${user.UserName} (Console Password)`,
							resourceArn: user.Arn,
							status: ComplianceStatus.ERROR,
							message: `Error checking login profile: ${error.message}`
						});
					}
				}

				// Check access keys
				try {
					const accessKeys = await iamClient.send(
						new ListAccessKeysCommand({ UserName: user.UserName })
					);

					if (accessKeys.AccessKeyMetadata) {
						for (const key of accessKeys.AccessKeyMetadata) {
							if (key.CreateDate) {
								const keyAge = Math.floor(
									(Date.now() - key.CreateDate.getTime()) / (1000 * 60 * 60 * 24)
								);

								results.checks.push({
									resourceName: `${user.UserName} (Access Key: ${key.AccessKeyId})`,
									resourceArn: user.Arn,
									status:
										keyAge <= MAX_ACCESS_KEY_AGE_DAYS
											? ComplianceStatus.PASS
											: ComplianceStatus.FAIL,
									message:
										keyAge > MAX_ACCESS_KEY_AGE_DAYS
											? `Access key is ${keyAge} days old (max: ${MAX_ACCESS_KEY_AGE_DAYS})`
											: undefined
								});
							}
						}
					}
				} catch (error: any) {
					results.checks.push({
						resourceName: `${user.UserName} (Access Keys)`,
						resourceArn: user.Arn,
						status: ComplianceStatus.ERROR,
						message: `Error checking access keys: ${error.message}`
					});
				}
			}
		}

		// Check Aurora DB Instances
		const dbInstances = await rdsClient.send(new DescribeDBInstancesCommand({}));

		if (!dbInstances.DBInstances || dbInstances.DBInstances.length === 0) {
			results.checks.push({
				resourceName: "Aurora DB Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Aurora DB instances found"
			});
		} else {
			for (const instance of dbInstances.DBInstances) {
				if (instance.Engine?.includes("aurora")) {
					results.checks.push({
						resourceName: instance.DBInstanceIdentifier || "Unknown Aurora Instance",
						resourceArn: instance.DBInstanceArn,
						status: ComplianceStatus.INFO,
						message: "Manual verification required for Aurora database password rotation"
					});
				}
			}
		}
	} catch (error: any) {
		results.checks.push({
			resourceName: "Password Rotation Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking password rotation: ${error.message}`
		});
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkPasswordRotationCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Passwords are Regularly Rotated",
	description:
		"Regularly rotating your Aurora passwords is critical to access management, contributing to maintaining system security. The database password can be rotated in Amazon Aurora, but the access keys refer to the rotation of AWS IAM User access keys",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_IAM.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkPasswordRotationCompliance
} satisfies RuntimeTest;
