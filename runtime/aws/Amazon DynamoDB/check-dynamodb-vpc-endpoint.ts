import { EC2Client, DescribeVpcEndpointsCommand } from "@aws-sdk/client-ec2";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllDynamoDBTables } from "./get-all-dynamodb-tables.js";

async function checkDynamoDBVPCEndpointCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const ec2Client = new EC2Client({ region });
	const dynamoClient = new DynamoDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all DynamoDB tables using pagination
		const tableNames = await getAllDynamoDBTables(dynamoClient);

		if (tableNames.length === 0) {
			results.checks = [
				{
					resourceName: "DynamoDB Tables",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No DynamoDB tables found in the region"
				}
			];
			return results;
		}

		// Check for DynamoDB VPC endpoints
		const endpoints = await ec2Client.send(
			new DescribeVpcEndpointsCommand({
				Filters: [
					{
						Name: "service-name",
						Values: [`com.amazonaws.${region}.dynamodb`]
					}
				]
			})
		);

		const hasEndpoint = endpoints.VpcEndpoints && endpoints.VpcEndpoints.length > 0;

		// For each table, check if VPC endpoint exists
		for (const tableName of tableNames) {
			results.checks.push({
				resourceName: tableName,
				status: hasEndpoint ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasEndpoint
					? undefined
					: "No VPC endpoint for DynamoDB is configured. Configure a VPC endpoint to securely access DynamoDB within your VPC."
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DynamoDB VPC endpoints: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkDynamoDBVPCEndpointCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon DynamoDB",
	shortServiceName: "dynamodb",
	title: "Ensure VPC Endpoints are configured for DynamoDB",
	description:
		"Using VPC endpoints with Amazon DynamoDB allows you to securely access DynamoDB resources within your Amazon Virtual Private Cloud (VPC). This keeps your traffic off the public internet.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_4.5",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDynamoDBVPCEndpointCompliance
} satisfies RuntimeTest;
