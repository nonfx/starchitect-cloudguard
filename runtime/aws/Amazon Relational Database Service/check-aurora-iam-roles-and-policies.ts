import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { RDSClient, DescribeDBClustersCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface PolicyStatement {
	Sid?: string;
	Effect: string;
	Action: string | string[];
	Resource: string | string[];
}

interface PolicyDocument {
	Version: string;
	Statement: PolicyStatement | PolicyStatement[];
}

function isValidRDSPolicy(policyDoc: PolicyDocument, clusterArn?: string): boolean {
	const statements = Array.isArray(policyDoc.Statement)
		? policyDoc.Statement
		: [policyDoc.Statement];

	return statements.some(statement => {
		const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
		const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

		// Check if this is a valid RDS policy
		const hasRDSActions = actions.some(action => {
			// Check for specific RDS actions or wildcard
			return action === "rds:*" || action.startsWith("rds:");
		});

		const hasValidResource = resources.some(resource => {
			if (clusterArn) {
				// Check for specific cluster access
				return (
					resource === clusterArn ||
					resource === `${clusterArn}:*` ||
					resource === "arn:aws:rds:*:*:*" ||
					resource === "*"
				);
			} else {
				// Check for general RDS access
				return resource.includes("arn:aws:rds:") || resource === "*";
			}
		});

		return statement.Effect === "Allow" && hasRDSActions && hasValidResource;
	});
}

async function checkAuroraIamRolesAndPolicies(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const iamClient = new IAMClient({ region });
	const rdsClient = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get Aurora clusters
		const clusters = await rdsClient.send(new DescribeDBClustersCommand({}));

		if (!clusters.DBClusters || clusters.DBClusters.length === 0) {
			results.checks.push({
				resourceName: "Aurora Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Aurora clusters found in the region"
			});
			return results;
		}

		// Get all IAM policies
		const policies = await iamClient.send(new ListPoliciesCommand({ Scope: "Local" }));
		const policyDocuments: { [key: string]: PolicyDocument } = {};

		// Fetch policy documents
		if (policies.Policies) {
			for (const policy of policies.Policies) {
				if (!policy.Arn || !policy.DefaultVersionId) continue;

				try {
					const versionResponse = await iamClient.send(
						new GetPolicyVersionCommand({
							PolicyArn: policy.Arn,
							VersionId: policy.DefaultVersionId
						})
					);

					if (versionResponse.PolicyVersion?.Document) {
						policyDocuments[policy.Arn] = JSON.parse(
							decodeURIComponent(versionResponse.PolicyVersion.Document)
						);
					}
				} catch (error) {
					console.log(`Error fetching policy document for ${policy.Arn}:`, error);
				}
			}
		}

		// Check each cluster for proper IAM policies
		for (const cluster of clusters.DBClusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) continue;

			let hasValidPolicy = false;

			// Check all policies for RDS access
			for (const policyDoc of Object.values(policyDocuments)) {
				if (isValidRDSPolicy(policyDoc, cluster.DBClusterArn)) {
					hasValidPolicy = true;
					break;
				}
			}

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: hasValidPolicy ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasValidPolicy
					? undefined
					: "No valid IAM policy found that grants access to this RDS cluster"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "IAM and RDS Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking IAM configuration: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAuroraIamRolesAndPolicies(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure IAM Roles and Policies are Created",
	description:
		"AWS Identity and Access Management (IAM) helps manage access to AWS resources. While you cannot directly associate IAM roles with Amazon Aurora instances, you can use IAM roles and policies to define which AWS IAM users and groups have management permissions for Amazon RDS resources and what actions they can perform",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_2.5",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkAuroraIamRolesAndPolicies,
	serviceName: "Amazon Relational Database Service"
} satisfies RuntimeTest;
