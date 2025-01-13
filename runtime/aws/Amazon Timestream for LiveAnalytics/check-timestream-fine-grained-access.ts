import type { Database } from "@aws-sdk/client-timestream-write";
import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllTimestreamDatabases } from "./get-all-timestream-databases.js";

interface PolicyDocument {
	Version: string;
	Statement: PolicyStatement[];
}

interface PolicyStatement {
	Effect: string;
	Action: string | string[];
	Resource: string | string[];
	Condition?: {
		[key: string]: {
			[key: string]: string | string[];
		};
	};
}

interface FineGrainedAccessResult {
	hasTableLevelAccess: boolean;
	hasColumnLevelAccess: boolean;
	hasRowLevelAccess: boolean;
}

async function checkTimestreamFineGrainedAccess(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = { checks: [] };

	try {
		// Get all Timestream databases using the utility function
		const databases = await getAllTimestreamDatabases(region);

		if (databases.length === 0) {
			results.checks.push({
				resourceName: "No Timestream Databases",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Timestream databases found in the region"
			});
			return results;
		}

		// Fetch all IAM policies
		const policies = [];
		let policyNextToken: string | undefined;
		do {
			const listPoliciesCommand = new ListPoliciesCommand({
				Marker: policyNextToken,
				Scope: "Local"
			});
			const policiesResponse = await iamClient.send(listPoliciesCommand);
			if (policiesResponse.Policies) {
				policies.push(...policiesResponse.Policies);
			}
			policyNextToken = policiesResponse.Marker;
		} while (policyNextToken);

		// Check each database for fine-grained access controls in any policy
		for (const database of databases) {
			const databaseName = database.DatabaseName;
			if (!databaseName) continue;

			let hasFineGrainedAccessInAnyPolicy = false;
			const accessControls = new Set<string>();

			// Check all policies for this database
			for (const policy of policies) {
				if (!policy.Arn || !policy.DefaultVersionId) continue;

				try {
					const versionCommand = new GetPolicyVersionCommand({
						PolicyArn: policy.Arn,
						VersionId: policy.DefaultVersionId
					});
					const versionResponse = await iamClient.send(versionCommand);
					const policyDoc = versionResponse.PolicyVersion?.Document;

					if (policyDoc) {
						const document: PolicyDocument = JSON.parse(decodeURIComponent(policyDoc));
						const accessResult = analyzePolicyAccess(document, [databaseName]);

						if (accessResult.hasTableLevelAccess) accessControls.add("table-level");
						if (accessResult.hasColumnLevelAccess) accessControls.add("column-level");
						if (accessResult.hasRowLevelAccess) accessControls.add("row-level");

						if (
							accessResult.hasTableLevelAccess ||
							accessResult.hasColumnLevelAccess ||
							accessResult.hasRowLevelAccess
						) {
							hasFineGrainedAccessInAnyPolicy = true;
						}
					}
				} catch (error) {
					results.checks.push({
						resourceName: databaseName,
						resourceArn: database.Arn,
						status: ComplianceStatus.ERROR,
						message: `Error analyzing policy ${policy.PolicyName}: ${error instanceof Error ? error.message : String(error)}`
					});
					return results;
				}
			}

			let message: string;
			if (hasFineGrainedAccessInAnyPolicy) {
				message = `Implements ${Array.from(accessControls).join(", ")} access controls`;
			} else {
				message =
					"No fine-grained access controls found. Consider implementing:\n" +
					"- Table-level access controls\n" +
					"- Column-level access controls\n" +
					"- Row-level access controls";
			}

			results.checks.push({
				resourceName: databaseName,
				resourceArn: database.Arn,
				status: hasFineGrainedAccessInAnyPolicy ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Timestream Access Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Timestream access: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

function analyzePolicyAccess(
	policyDoc: PolicyDocument,
	databases: string[]
): FineGrainedAccessResult {
	const result: FineGrainedAccessResult = {
		hasTableLevelAccess: false,
		hasColumnLevelAccess: false,
		hasRowLevelAccess: false
	};

	for (const statement of policyDoc.Statement) {
		if (statement.Effect !== "Allow") continue;

		// Skip if Action or Resource is undefined
		if (!statement.Action || !statement.Resource) continue;

		const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
		const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

		// Filter out non-string values and convert to string array
		const validActions = actions.filter((action): action is string => typeof action === "string");
		const validResources = resources.filter(
			(resource): resource is string => typeof resource === "string"
		);

		// Skip if using broad access patterns
		if (validActions.some(action => action === "timestream:*" || action === "*")) {
			if (validResources.some(resource => resource === "*" || resource.endsWith("*"))) {
				continue;
			}
		}

		// Check for table-level access
		result.hasTableLevelAccess ||= validResources.some(
			resource => resource.includes("table/") && !resource.endsWith("*")
		);

		// Check for column-level access via conditions
		if (statement.Condition) {
			// Check for column restrictions
			result.hasColumnLevelAccess ||= Object.entries(statement.Condition).some(
				([key, value]) =>
					key.toLowerCase().includes("column") ||
					Object.keys(value).some(k => k.toLowerCase().includes("column"))
			);

			// Check for row-level filtering via measure/dimension conditions
			result.hasRowLevelAccess ||= Object.entries(statement.Condition).some(
				([key, value]) =>
					key.toLowerCase().includes("measure") ||
					key.toLowerCase().includes("dimension") ||
					Object.keys(value).some(
						k => k.toLowerCase().includes("measure") || k.toLowerCase().includes("dimension")
					)
			);
		}
	}

	return result;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkTimestreamFineGrainedAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Fine-Grained Access Control is Enabled",
	description:
		"Leverage Timestream's fine-grained access control capabilities to control table or row level access. Define access policies that limit access to specific tables, columns, or rows based on user roles or conditions. Implement data filtering and row-level security to restrict access to sensitive information",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_10.5",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkTimestreamFineGrainedAccess,
	serviceName: "Amazon Timestream for LiveAnalytics",
	shortServiceName: "timestream"
} satisfies RuntimeTest;
