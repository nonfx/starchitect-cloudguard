import { DocDBClient, DescribeDBClusterParameterGroupsCommand } from "@aws-sdk/client-docdb";
import { getAllDocDBClusters } from "../../utils/aws/get-all-docdb-clusters.js";
import {
	IAMClient,
	ListRolesCommand,
	GetRoleCommand,
	ListAttachedRolePoliciesCommand
} from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkDocumentDBAuthAccessControl(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const docdbClient = new DocDBClient({ region });
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const clusters = (await getAllDocDBClusters(docdbClient)) ?? [];

		if (clusters.length === 0) {
			results.checks.push({
				resourceName: "No DocumentDB Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No DocumentDB clusters found in the region"
			});
			return results;
		}

		for (const cluster of clusters) {
			if (!cluster.DBClusterIdentifier) {
				continue;
			}

			try {
				// Check if IAM authentication is enabled
				const iamAuthEnabled = (cluster as any).EnableIAMDatabaseAuthentication === true;

				// Check associated roles
				let hasValidRoles = false;
				if (cluster.AssociatedRoles && cluster.AssociatedRoles.length > 0) {
					for (const roleInfo of cluster.AssociatedRoles) {
						if (roleInfo.RoleArn) {
							const roleName = roleInfo.RoleArn.split("/").pop();
							if (roleName) {
								const roleResponse = await iamClient.send(
									new GetRoleCommand({ RoleName: roleName })
								);
								if (roleResponse.Role) {
									// Check attached policies
									const policies = await iamClient.send(
										new ListAttachedRolePoliciesCommand({
											RoleName: roleName
										})
									);

									if (policies.AttachedPolicies && policies.AttachedPolicies.length > 0) {
										hasValidRoles = true;
										break; // Exit after finding first valid role
									}
								}
							}
						}
					}
				}

				// Check parameter group for auth settings
				const paramGroups = await docdbClient.send(
					new DescribeDBClusterParameterGroupsCommand({
						DBClusterParameterGroupName: cluster.DBClusterParameterGroup
					})
				);

				const hasSecureAuth =
					paramGroups.DBClusterParameterGroups && paramGroups.DBClusterParameterGroups.length > 0;

				const isCompliant = iamAuthEnabled && hasValidRoles && hasSecureAuth;

				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: `Cluster does not have proper authentication and access controls configured (IAM Auth: ${iamAuthEnabled}, Valid Roles: ${hasValidRoles}, Secure Auth: ${hasSecureAuth})`
				});
			} catch (error) {
				results.checks.push({
					resourceName: cluster.DBClusterIdentifier,
					resourceArn: cluster.DBClusterArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking cluster configuration: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "DocumentDB Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking DocumentDB clusters: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDocumentDBAuthAccessControl(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure to Implement Access Control and Authentication",
	description:
		"Configure authentication mechanisms for your DocumentDB instances, such as using AWS Identity and Access Management (IAM) users or database users. Define appropriate user roles and permissions to control access to the DocumentDB instances and databases",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.5",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkDocumentDBAuthAccessControl,
	serviceName: "Amazon DocumentDB",
	shortServiceName: "docdb"
} satisfies RuntimeTest;
