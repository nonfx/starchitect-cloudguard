import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import {
	IAMClient,
	GetRolePolicyCommand,
	ListRolePoliciesCommand,
	ListAttachedRolePoliciesCommand,
	GetPolicyVersionCommand
} from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface PolicyDocument {
	Version: string;
	Statement: Array<{
		Effect: string;
		Action: string | string[];
		Resource: string | string[];
	}>;
}

async function checkAuroraLeastPrivilegeCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const rdsClient = new RDSClient({ region });
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DB instances
		const dbInstances = await rdsClient.send(new DescribeDBInstancesCommand({}));

		// Filter Aurora instances
		const auroraInstances =
			dbInstances.DBInstances?.filter(
				instance =>
					instance.Engine === "aurora" ||
					instance.Engine === "aurora-mysql" ||
					instance.Engine === "aurora-postgresql"
			) || [];

		if (auroraInstances.length === 0) {
			results.checks.push({
				resourceName: "Aurora Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Aurora instances found"
			});
			return results;
		}

		for (const instance of auroraInstances) {
			if (!instance.DBInstanceArn || !instance.DBInstanceIdentifier) continue;

			// Check associated IAM roles
			if (instance.AssociatedRoles) {
				for (const role of instance.AssociatedRoles) {
					if (!role.RoleArn) continue;

					const roleName = role.RoleArn.split("/").pop();
					if (!roleName) continue;

					try {
						// Check inline policies
						const inlinePolicies = await iamClient.send(
							new ListRolePoliciesCommand({ RoleName: roleName })
						);

						for (const policyName of inlinePolicies.PolicyNames || []) {
							const policyDetails = await iamClient.send(
								new GetRolePolicyCommand({
									RoleName: roleName,
									PolicyName: policyName
								})
							);

							const hasOverPrivileges = checkPolicyPrivileges(policyDetails.PolicyDocument);
							if (hasOverPrivileges) {
								results.checks.push({
									resourceName: instance.DBInstanceIdentifier,
									resourceArn: instance.DBInstanceArn,
									status: ComplianceStatus.FAIL,
									message: `Role ${role.RoleArn} has excessive privileges in inline policy ${policyName}`
								});
								continue;
							}
						}

						// Check attached policies
						const attachedPolicies = await iamClient.send(
							new ListAttachedRolePoliciesCommand({ RoleName: roleName })
						);

						for (const policy of attachedPolicies.AttachedPolicies || []) {
							if (!policy.PolicyArn) continue;

							const policyVersion = await iamClient.send(
								new GetPolicyVersionCommand({
									PolicyArn: policy.PolicyArn,
									VersionId: "v1"
								})
							);

							if (policyVersion.PolicyVersion?.Document) {
								const hasOverPrivileges = checkPolicyPrivileges(
									policyVersion.PolicyVersion.Document
								);
								if (hasOverPrivileges) {
									results.checks.push({
										resourceName: instance.DBInstanceIdentifier,
										resourceArn: instance.DBInstanceArn,
										status: ComplianceStatus.FAIL,
										message: `Role ${role.RoleArn} has excessive privileges in attached policy ${policy.PolicyName}`
									});
									continue;
								}
							}
						}

						// If we get here, all policies are compliant
						results.checks.push({
							resourceName: instance.DBInstanceIdentifier,
							resourceArn: instance.DBInstanceArn,
							status: ComplianceStatus.PASS,
							message: `Role ${role.RoleArn} follows least privilege principle`
						});
					} catch (error) {
						results.checks.push({
							resourceName: instance.DBInstanceIdentifier,
							resourceArn: instance.DBInstanceArn,
							status: ComplianceStatus.ERROR,
							message: `Error checking role ${role.RoleArn}: ${error instanceof Error ? error.message : String(error)}`
						});
					}
				}
			} else {
				results.checks.push({
					resourceName: instance.DBInstanceIdentifier,
					resourceArn: instance.DBInstanceArn,
					status: ComplianceStatus.PASS,
					message: "No IAM roles associated with this instance"
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Aurora Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Aurora instances: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

function checkPolicyPrivileges(policyDocument: string | undefined): boolean {
	if (!policyDocument) return false;

	try {
		const policy: PolicyDocument =
			typeof policyDocument === "string"
				? JSON.parse(decodeURIComponent(policyDocument))
				: policyDocument;

		return policy.Statement.some(stmt => {
			const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
			const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource];

			return (
				stmt.Effect === "Allow" &&
				(actions.includes("*") || actions.includes("rds:*")) &&
				resources.includes("*")
			);
		});
	} catch {
		return false;
	}
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkAuroraLeastPrivilegeCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Least Privilege Access",
	description:
		"Use the principle of least privilege when granting access to your Amazon Aurora resources. This principle of least privilege (POLP) is a computer security concept where users are given the minimum access levels necessary to complete their job functions. In Amazon Aurora, this can be implemented at various levels, including AWS IAM for managing AWS resources and within the database for managing database users and roles.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkAuroraLeastPrivilegeCompliance
} satisfies RuntimeTest;
