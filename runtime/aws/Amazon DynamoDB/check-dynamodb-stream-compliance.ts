import { DynamoDBClient, ListTablesCommand, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { LambdaClient, ListEventSourceMappingsCommand } from "@aws-sdk/client-lambda";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";

async function checkDynamoDBStreamCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const dynamoClient = new DynamoDBClient({ region });
	const lambdaClient = new LambdaClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DynamoDB tables
		const listTablesResponse = await dynamoClient.send(new ListTablesCommand({}));

		if (!listTablesResponse.TableNames || listTablesResponse.TableNames.length === 0) {
			results.checks.push({
				resourceName: "No DynamoDB Tables",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No DynamoDB tables found in the region"
			});
			return results;
		}

		// Get all Lambda event source mappings
		const eventSourceMappings = await lambdaClient.send(new ListEventSourceMappingsCommand({}));
		const dynamoDBEventSources = new Set(
			eventSourceMappings.EventSourceMappings?.filter(mapping =>
				mapping.EventSourceArn?.includes("dynamodb")
			).map(mapping => mapping.EventSourceArn) || []
		);

		// Check each table
		for (const tableName of listTablesResponse.TableNames) {
			try {
				const tableDetails = await dynamoClient.send(
					new DescribeTableCommand({ TableName: tableName })
				);

				if (!tableDetails.Table) {
					results.checks.push({
						resourceName: tableName,
						status: ComplianceStatus.ERROR,
						message: "Unable to retrieve table details"
					});
					continue;
				}

				const streamEnabled = tableDetails.Table.StreamSpecification?.StreamEnabled;
				const streamArn = tableDetails.Table.LatestStreamArn;
				const hasLambdaIntegration = streamArn ? dynamoDBEventSources.has(streamArn) : false;

				if (!streamEnabled) {
					results.checks.push({
						resourceName: tableName,
						resourceArn: tableDetails.Table.TableArn,
						status: ComplianceStatus.FAIL,
						message: "DynamoDB Streams is not enabled for this table"
					});
				} else if (!hasLambdaIntegration) {
					results.checks.push({
						resourceName: tableName,
						resourceArn: tableDetails.Table.TableArn,
						status: ComplianceStatus.FAIL,
						message: "DynamoDB Streams is enabled but no Lambda function is configured"
					});
				} else {
					results.checks.push({
						resourceName: tableName,
						resourceArn: tableDetails.Table.TableArn,
						status: ComplianceStatus.PASS,
						message: undefined
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: tableName,
					status: ComplianceStatus.ERROR,
					message: `Error checking table: ${error instanceof Error ? error.message : String(error)}`
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
	const region = process.env.AWS_REGION;
	const results = await checkDynamoDBStreamCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon DynamoDB",
	shortServiceName: "dynamodb",
	title: "Ensure DynamoDB Streams and AWS Lambda for Automated Compliance Checking is Enabled",
	description:
		"Enabling DynamoDB Streams and integrating AWS Lambda allows you to automate compliance checking and perform actions based on changes made to your DynamoDB data.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_4.6",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDynamoDBStreamCompliance
} satisfies RuntimeTest;
