import {
	CloudTrailClient,
	ListTrailsCommand,
	GetEventSelectorsCommand
} from "@aws-sdk/client-cloudtrail";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllDynamoDBTables } from "../../utils/aws/get-all-dynamodb-tables.js";

async function getAccountId(region: string): Promise<string> {
	const stsClient = new STSClient({ region });
	const command = new GetCallerIdentityCommand({});
	const response = await stsClient.send(command);
	return response.Account || "";
}

async function getAllCloudTrails(client: CloudTrailClient) {
	const trails = [];
	let nextToken: string | undefined;

	do {
		const command = new ListTrailsCommand({
			NextToken: nextToken
		});
		const response = await client.send(command);

		if (response.Trails) {
			trails.push(...response.Trails);
		}

		nextToken = response.NextToken;
	} while (nextToken);

	return trails;
}

async function checkDynamoDBAuditLogging(region: string = "us-east-1"): Promise<ComplianceReport> {
	const cloudTrailClient = new CloudTrailClient({ region });
	const dynamoDBClient = new DynamoDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DynamoDB tables using pagination
		const tableNames = await getAllDynamoDBTables(dynamoDBClient);

		if (tableNames.length === 0) {
			results.checks.push({
				resourceName: "No DynamoDB Tables",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No DynamoDB tables found in the region"
			});
			return results;
		}

		// Get all CloudTrail trails using pagination
		const trails = await getAllCloudTrails(cloudTrailClient);

		if (trails.length === 0) {
			for (const tableName of tableNames) {
				results.checks.push({
					resourceName: tableName,
					status: ComplianceStatus.FAIL,
					message: "No CloudTrail trails configured for audit logging"
				});
			}
			return results;
		}

		// Track which tables are being logged
		const loggedTables = new Set<string>();

		// Check each trail for DynamoDB logging
		for (const trail of trails) {
			if (!trail.TrailARN) continue;

			try {
				// Get event selectors for the trail
				const getEventSelectorsCommand = new GetEventSelectorsCommand({
					TrailName: trail.TrailARN
				});
				const eventSelectorsResponse = await cloudTrailClient.send(getEventSelectorsCommand);

				// Check standard event selectors
				if (eventSelectorsResponse.EventSelectors) {
					for (const selector of eventSelectorsResponse.EventSelectors) {
						if (selector.DataResources) {
							for (const resource of selector.DataResources) {
								if (resource.Type === "AWS::DynamoDB::Table") {
									// If Values array exists, check for specific tables
									if (resource.Values && resource.Values.length > 0) {
										const accountId = await getAccountId(region);
										for (const tableName of tableNames) {
											const tableArn = `arn:aws:dynamodb:${region}:${accountId}:table/${tableName}`;
											if (
												resource.Values.some(
													value =>
														value === tableArn || // Exact table match
														value.endsWith(":table/*") || // Wildcard table match
														value === "arn:aws:dynamodb" || // All DynamoDB resources
														value.startsWith("arn:aws:dynamodb:") // Region-specific all DynamoDB resources
												)
											) {
												loggedTables.add(tableName);
											}
										}
									} else {
										// If no Values array, all tables are logged
										tableNames.forEach(tableName => loggedTables.add(tableName));
									}
								}
							}
						}
					}
				}

				// Check advanced event selectors
				if (eventSelectorsResponse.AdvancedEventSelectors) {
					for (const selector of eventSelectorsResponse.AdvancedEventSelectors) {
						if (selector.FieldSelectors) {
							// Check if this selector is for DynamoDB tables
							const isDynamoDBType = selector.FieldSelectors.some(
								field =>
									field.Field === "resources.type" &&
									field.Equals &&
									field.Equals.includes("AWS::DynamoDB::Table")
							);

							if (isDynamoDBType) {
								// Look for resources.ARN field selector
								const arnSelector = selector.FieldSelectors.find(
									field => field.Field === "resources.ARN"
								);

								if (arnSelector?.Equals) {
									// If specific ARNs are listed, check if table ARN is in the list
									const accountId = await getAccountId(region);
									for (const tableName of tableNames) {
										const tableArn = `arn:aws:dynamodb:${region}:${accountId}:table/${tableName}`;
										if (arnSelector.Equals.includes(tableArn)) {
											loggedTables.add(tableName);
										}
									}
								} else {
									// If no resources.ARN field exists, all DynamoDB tables are included
									tableNames.forEach(tableName => loggedTables.add(tableName));
								}
							}
						}
					}
				}
			} catch (error) {
				console.error(`Error checking trail ${trail.TrailARN}: ${error}`);
			}
		}

		// Report compliance for each table based on whether it's being logged
		for (const tableName of tableNames) {
			const isLogged = loggedTables.has(tableName);
			results.checks.push({
				resourceName: tableName,
				status: isLogged ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isLogged
					? "CloudTrail logging properly configured for this DynamoDB table"
					: "This DynamoDB table does not have audit logging enabled via CloudTrail"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "DynamoDB Audit Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking DynamoDB audit logging: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkDynamoDBAuditLogging(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon DynamoDB",
	shortServiceName: "dynamodb",
	title: "Ensure Monitor and Audit Activity is enabled - Audit Logging",
	description:
		"Regular monitoring and auditing of activity in Amazon DynamoDB help ensure your database's security, performance, and compliance.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_4.7",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkDynamoDBAuditLogging
} satisfies RuntimeTest;
