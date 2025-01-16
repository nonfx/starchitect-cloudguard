import { DynamoDBClient, DescribeContinuousBackupsCommand } from "@aws-sdk/client-dynamodb";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllDynamoDBTables } from "../../utils/aws/get-all-dynamodb-tables.js";

async function checkDynamoDBPITRCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new DynamoDBClient({ region });
	const stsClient = new STSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get AWS account ID
		const identity = await stsClient.send(new GetCallerIdentityCommand({}));
		const accountId = identity.Account;
		if (!accountId) {
			throw new Error("Failed to get AWS account ID");
		}

		// Get all DynamoDB tables using pagination
		const tables = await getAllDynamoDBTables(client);

		if (tables.length === 0) {
			results.checks.push({
				resourceName: "No DynamoDB Tables",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No DynamoDB tables found in the region"
			});
			return results;
		}

		// Check PITR status for each table
		for (const tableName of tables) {
			try {
				const backupsCommand = new DescribeContinuousBackupsCommand({
					TableName: tableName
				});
				const backupsResponse = await client.send(backupsCommand);

				if (!backupsResponse.ContinuousBackupsDescription) {
					results.checks.push({
						resourceName: tableName,
						status: ComplianceStatus.ERROR,
						message: "Unable to get continuous backups description"
					});
					continue;
				}

				const pitrEnabled =
					backupsResponse.ContinuousBackupsDescription.PointInTimeRecoveryDescription
						?.PointInTimeRecoveryStatus === "ENABLED";

				const pitrDescription =
					backupsResponse.ContinuousBackupsDescription.PointInTimeRecoveryDescription;
				const tableArn = `arn:aws:dynamodb:${region}:${accountId}:table/${tableName}`;

				results.checks.push({
					resourceName: tableName,
					resourceArn: tableArn,
					status: pitrEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: pitrEnabled
						? `PITR enabled with restore window from ${pitrDescription?.EarliestRestorableDateTime?.toISOString()} to ${pitrDescription?.LatestRestorableDateTime?.toISOString()}`
						: "Point-in-time recovery (PITR) is not enabled for this table"
				});
			} catch (error) {
				results.checks.push({
					resourceName: tableName,
					status: ComplianceStatus.ERROR,
					message: `Error checking table PITR status: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "DynamoDB Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking DynamoDB tables: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkDynamoDBPITRCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon DynamoDB",
	shortServiceName: "dynamodb",
	title: "DynamoDB tables should have point-in-time recovery enabled",
	description:
		"This control checks whether point-in-time recovery (PITR) is enabled for DynamoDB tables. PITR provides continuous backups of your DynamoDB table data, allowing you to restore to any point in time within the last 35 days.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_DynamoDB.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDynamoDBPITRCompliance
} satisfies RuntimeTest;
