import { DynamoDBClient, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllDynamoDBTables } from "./get-all-dynamodb-tables.js";

async function checkDynamoDBDeletionProtection(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new DynamoDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DynamoDB tables using pagination
		const tables = await getAllDynamoDBTables(client);

		if (tables.length === 0) {
			results.checks = [
				{
					resourceName: "No DynamoDB Tables",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No DynamoDB tables found in the region"
				}
			];
			return results;
		}

		// Check each table for deletion protection
		for (const tableName of tables) {
			try {
				const describeCommand = new DescribeTableCommand({
					TableName: tableName
				});
				const tableDetails = await client.send(describeCommand);

				if (!tableDetails.Table) {
					results.checks.push({
						resourceName: tableName,
						status: ComplianceStatus.ERROR,
						message: "Unable to get table details"
					});
					continue;
				}

				const isDeletionProtected = tableDetails.Table.DeletionProtectionEnabled === true;

				results.checks.push({
					resourceName: tableName,
					resourceArn: tableDetails.Table.TableArn,
					status: isDeletionProtected ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isDeletionProtected
						? undefined
						: "DynamoDB table does not have deletion protection enabled"
				});
			} catch (error) {
				results.checks.push({
					resourceName: tableName,
					status: ComplianceStatus.ERROR,
					message: `Error checking table: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "DynamoDB Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DynamoDB tables: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDynamoDBDeletionProtection(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon DynamoDB",
	shortServiceName: "dynamodb",
	title: "DynamoDB tables should have deletion protection enabled",
	description:
		"DynamoDB tables must have deletion protection enabled to prevent accidental deletion and maintain business continuity.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_DynamoDB.6",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDynamoDBDeletionProtection
} satisfies RuntimeTest;
