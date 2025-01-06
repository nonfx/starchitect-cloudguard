import { DynamoDBClient, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import {
	ApplicationAutoScalingClient,
	DescribeScalableTargetsCommand
} from "@aws-sdk/client-application-auto-scaling";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllDynamoDBTables } from "./get-all-dynamodb-tables.js";

async function checkDynamoDBAutoScalingCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const dynamoClient = new DynamoDBClient({ region });
	const autoScalingClient = new ApplicationAutoScalingClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DynamoDB tables using pagination
		const tableNames = await getAllDynamoDBTables(dynamoClient);

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

		for (const tableName of tableNames) {
			try {
				// Get table details
				const tableResponse = await dynamoClient.send(
					new DescribeTableCommand({
						TableName: tableName
					})
				);

				if (!tableResponse.Table) {
					results.checks.push({
						resourceName: tableName,
						status: ComplianceStatus.ERROR,
						message: "Unable to get table details"
					});
					continue;
				}

				// Check if table uses on-demand billing
				if (tableResponse.Table.BillingModeSummary?.BillingMode === "PAY_PER_REQUEST") {
					results.checks.push({
						resourceName: tableName,
						resourceArn: tableResponse.Table.TableArn,
						status: ComplianceStatus.PASS,
						message: "Table uses on-demand capacity mode"
					});
					continue;
				}

				// For provisioned tables, check auto-scaling targets
				const scalableTargets = await autoScalingClient.send(
					new DescribeScalableTargetsCommand({
						ServiceNamespace: "dynamodb",
						ResourceIds: [`table/${tableName}`]
					})
				);

				const hasAutoScaling =
					scalableTargets.ScalableTargets && scalableTargets.ScalableTargets.length > 0;

				results.checks.push({
					resourceName: tableName,
					resourceArn: tableResponse.Table.TableArn,
					status: hasAutoScaling ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasAutoScaling
						? "Table has auto-scaling configured"
						: "Table uses provisioned capacity without auto-scaling"
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
	const results = await checkDynamoDBAutoScalingCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon DynamoDB",
	shortServiceName: "dynamodb",
	title: "DynamoDB tables should automatically scale capacity with demand",
	description:
		"DynamoDB tables must implement automatic capacity scaling through on-demand mode or provisioned mode with auto-scaling to prevent throttling and maintain availability.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_DynamoDB.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDynamoDBAutoScalingCompliance
} satisfies RuntimeTest;
