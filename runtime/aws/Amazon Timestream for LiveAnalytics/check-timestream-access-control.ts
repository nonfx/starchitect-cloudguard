import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { getAllTimestreamDatabases } from "./get-all-timestream-databases.js";
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

// Define the Database type
interface Database {
	DatabaseName?: string; // Make it optional if it might not always exist
	// Add other properties if needed
}

async function checkTimestreamAccessControl(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = { checks: [] };

	try {
		// Fetch all Timestream databases
		const databases: Database[] = await getAllTimestreamDatabases(region);

		if (databases.length === 0) {
			results.checks.push({
				resourceName: "No Timestream Databases",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Timestream databases found in the region"
			});
			return results;
		}

		// Fetch all IAM policies
		let marker: string | undefined;
		const allPolicies = [];
		do {
			const policiesResponse = await iamClient.send(
				new ListPoliciesCommand({
					Marker: marker,
					Scope: "Local"
				})
			);
			allPolicies.push(...(policiesResponse.Policies || []));
			marker = policiesResponse.Marker;
		} while (marker);

		// Check each database for associated policies
		for (const database of databases) {
			if (!database.DatabaseName) continue; // Skip if DatabaseName is missing

			// Assert that database.DatabaseName is a string
			const databaseName = database.DatabaseName as string;

			let hasPolicy = false;

			// Check if any policy applies to the database
			for (const policy of allPolicies) {
				if (!policy.Arn || !policy.DefaultVersionId) continue;

				const versionResponse = await iamClient.send(
					new GetPolicyVersionCommand({
						PolicyArn: policy.Arn,
						VersionId: policy.DefaultVersionId
					})
				);

				if (versionResponse.PolicyVersion?.Document) {
					const policyDoc = JSON.parse(
						decodeURIComponent(versionResponse.PolicyVersion.Document)
					) as PolicyDocument;

					// Check if the policy applies to the database
					if (
						policyDoc.Statement.some(statement => {
							const resources = Array.isArray(statement.Resource)
								? statement.Resource
								: [statement.Resource];
							return resources.some(resource => resource.includes(databaseName));
						})
					) {
						hasPolicy = true;
						break;
					}
				}
			}

			results.checks.push({
				resourceName: database.DatabaseName,
				status: hasPolicy ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasPolicy ? "Policy found for the database" : "No policy found for the database"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Timestream Access Control Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Timestream access control: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkTimestreamAccessControl(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Access Control and Authentication is Enabled",
	description:
		"Utilize AWS Identity and Access Management (IAM) to control access to your Amazon Timestream resources. Define IAM policies that grant or deny permissions for specific Timestream actions and resources.",
	controls: [
		{
			id: "CIS-AWS-Timestream-Services-Benchmark_v1.0.0_10.4.a",
			document: "CIS-AWS-Timestream-Services-Benchmark_v1.0.0"
		},
		{
			id: "CIS-AWS-Timestream-Services-Benchmark_v1.0.0_10.4.b",
			document: "CIS-AWS-Timestream-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkTimestreamAccessControl,
	serviceName: "Amazon Timestream for LiveAnalytics",
	shortServiceName: "timestream"
} satisfies RuntimeTest;
