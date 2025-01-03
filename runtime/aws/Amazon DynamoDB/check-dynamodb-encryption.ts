import { DynamoDBClient, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllDynamoDBTables } from "./get-all-dynamodb-tables.js";

async function checkDynamoDBEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new DynamoDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DynamoDB tables using pagination
		const tableNames = await getAllDynamoDBTables(client);

		if (tableNames.length === 0) {
			results.checks = [
				{
					resourceName: "No DynamoDB Tables",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No DynamoDB tables found in the region"
				}
			];
			return results;
		}

		// Check each table for encryption configuration
		for (const tableName of tableNames) {
			try {
				const describeTableResponse = await client.send(
					new DescribeTableCommand({
						TableName: tableName
					})
				);

				if (!describeTableResponse.Table) {
					results.checks.push({
						resourceName: tableName,
						status: ComplianceStatus.ERROR,
						message: "Unable to retrieve table details"
					});
					continue;
				}

				const table = describeTableResponse.Table;
				const isEncrypted = table.SSEDescription?.Status === "ENABLED";

				results.checks.push({
					resourceName: tableName,
					resourceArn: table.TableArn,
					status: isEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isEncrypted
						? undefined
						: "DynamoDB table does not have encryption at rest enabled"
				});
			} catch (error) {
				results.checks.push({
					resourceName: tableName,
					status: ComplianceStatus.ERROR,
					message: `Error checking table encryption: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DynamoDB tables: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkDynamoDBEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon DynamoDB",
	shortServiceName: "dynamodb",
	title: "Ensure DynamoDB Encryption at Rest",
	description:
		"Encryption at rest in Amazon DynamoDB enhances the security of your data by encrypting it using AWS Key Management Service (AWS KMS) keys.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_4.3",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDynamoDBEncryption
} satisfies RuntimeTest;
