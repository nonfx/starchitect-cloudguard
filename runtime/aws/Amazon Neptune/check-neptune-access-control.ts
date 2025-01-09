import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import {
	IAMClient,
	ListRolesCommand,
	GetRolePolicyCommand,
	ListRolePoliciesCommand,
	ListAttachedRolePoliciesCommand,
	GetPolicyCommand,
	GetPolicyVersionCommand
} from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface PolicyDocument {
	Statement: Array<{
		Effect: string;
		Action: string | string[];
		Resource: string | string[];
	}>;
}

function hasWildcardAccess(policyDoc: PolicyDocument): boolean {
	return policyDoc.Statement.some(statement => {
		if (statement.Effect !== "Allow") return false;

		const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
		const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

		return (
			actions.some(action => action === "*" || action === "neptune-db:*") &&
			resources.some(resource => resource === "*" || resource.includes("*"))
		);
	});
}

async function checkNeptuneAccessControl(region: string = "us-east-1"): Promise<ComplianceReport> {
	const neptuneClient = new NeptuneClient({ region });
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = { checks: [] };

	try {
		// First check if any Neptune clusters exist
		const clusters = await neptuneClient.send(new DescribeDBClustersCommand({}));

		if (!clusters.DBClusters?.length) {
			results.checks.push({
				resourceName: "Neptune Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Neptune clusters found"
			});
			return results;
		}

		// Check all IAM roles since clusters exist
		const roles = await iamClient.send(new ListRolesCommand({}));

		for (const role of roles.Roles || []) {
			if (!role.RoleName) continue;

			let hasInvalidPolicy = false;

			// Check inline policies
			const inlinePolicies = await iamClient.send(
				new ListRolePoliciesCommand({
					RoleName: role.RoleName
				})
			);

			for (const policyName of inlinePolicies.PolicyNames || []) {
				const policyResponse = await iamClient.send(
					new GetRolePolicyCommand({
						RoleName: role.RoleName,
						PolicyName: policyName
					})
				);

				if (policyResponse.PolicyDocument) {
					const policyDoc = JSON.parse(decodeURIComponent(policyResponse.PolicyDocument));
					if (hasWildcardAccess(policyDoc)) {
						hasInvalidPolicy = true;
						break;
					}
				}
			}

			if (!hasInvalidPolicy) {
				// Check AWS managed policies
				const managedPolicies = await iamClient.send(
					new ListAttachedRolePoliciesCommand({
						RoleName: role.RoleName
					})
				);

				for (const policy of managedPolicies.AttachedPolicies || []) {
					if (!policy.PolicyArn) continue;

					const policyDetails = await iamClient.send(
						new GetPolicyCommand({
							PolicyArn: policy.PolicyArn
						})
					);

					if (policyDetails.Policy?.DefaultVersionId) {
						const policyVersion = await iamClient.send(
							new GetPolicyVersionCommand({
								PolicyArn: policy.PolicyArn,
								VersionId: policyDetails.Policy.DefaultVersionId
							})
						);

						if (policyVersion.PolicyVersion?.Document) {
							const policyDoc = JSON.parse(
								decodeURIComponent(policyVersion.PolicyVersion.Document)
							);
							if (hasWildcardAccess(policyDoc)) {
								hasInvalidPolicy = true;
								break;
							}
						}
					}
				}
			}

			// Add individual check result for each role
			results.checks.push({
				resourceName: role.RoleName,
				resourceArn: role.Arn,
				status: hasInvalidPolicy ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: hasInvalidPolicy
					? "Role has overly permissive Neptune access with wildcard permissions"
					: "Role has properly configured Neptune access controls"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Neptune Access Control Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking IAM roles: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkNeptuneAccessControl(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon Neptune",
	shortServiceName: "neptune",
	title: "Ensure Authentication and Access Control is Enabled - access control",
	description:
		"This helps ensure that there are specific IAM roles and policies that are given the necessary information within a Neptune DB cluster to operate as needed.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_9.4",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkNeptuneAccessControl
} satisfies RuntimeTest;
