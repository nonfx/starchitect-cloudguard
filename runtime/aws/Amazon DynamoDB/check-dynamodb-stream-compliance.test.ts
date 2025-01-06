// @ts-nocheck
import { DynamoDBClient, ListTablesCommand, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { LambdaClient, ListEventSourceMappingsCommand } from "@aws-sdk/client-lambda";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDynamoDBStreamCompliance from "./check-dynamodb-stream-compliance";

const mockDynamoDBClient = mockClient(DynamoDBClient);
const mockLambdaClient = mockClient(LambdaClient);

const mockTable1 = {
	TableName: "table1",
	TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/table1",
	StreamSpecification: { StreamEnabled: true },
	LatestStreamArn: "arn:aws:dynamodb:us-east-1:123456789012:table/table1/stream/1"
};

const mockTable2 = {
	TableName: "table2",
	TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/table2",
	StreamSpecification: { StreamEnabled: false }
};

describe("checkDynamoDBStreamCompliance", () => {
	beforeEach(() => {
		mockDynamoDBClient.reset();
		mockLambdaClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when table has streams enabled and Lambda integration", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["table1"] })
				.on(DescribeTableCommand)
				.resolves({ Table: mockTable1 });

			mockLambdaClient.on(ListEventSourceMappingsCommand).resolves({
				EventSourceMappings: [
					{
						EventSourceArn: mockTable1.LatestStreamArn,
						FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:processor"
					}
				]
			});

			const result = await checkDynamoDBStreamCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("table1");
		});

		it("should return NOTAPPLICABLE when no tables exist", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: [] });

			const result = await checkDynamoDBStreamCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DynamoDB tables found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when streams are not enabled", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["table2"] })
				.on(DescribeTableCommand)
				.resolves({ Table: mockTable2 });

			mockLambdaClient.on(ListEventSourceMappingsCommand).resolves({
				EventSourceMappings: []
			});

			const result = await checkDynamoDBStreamCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("DynamoDB Streams is not enabled for this table");
		});

		it("should return FAIL when streams enabled but no Lambda integration", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["table1"] })
				.on(DescribeTableCommand)
				.resolves({ Table: mockTable1 });

			mockLambdaClient.on(ListEventSourceMappingsCommand).resolves({
				EventSourceMappings: []
			});

			const result = await checkDynamoDBStreamCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"DynamoDB Streams is enabled but no Lambda function is configured"
			);
		});

		it("should handle multiple tables with mixed compliance", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["table1", "table2"] })
				.on(DescribeTableCommand, { TableName: "table1" })
				.resolves({ Table: mockTable1 })
				.on(DescribeTableCommand, { TableName: "table2" })
				.resolves({ Table: mockTable2 });

			mockLambdaClient.on(ListEventSourceMappingsCommand).resolves({
				EventSourceMappings: [
					{
						EventSourceArn: mockTable1.LatestStreamArn,
						FunctionArn: "arn:aws:lambda:us-east-1:123456789012:function:processor"
					}
				]
			});

			const result = await checkDynamoDBStreamCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListTables fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).rejects(new Error("API Error"));

			const result = await checkDynamoDBStreamCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DynamoDB tables");
		});

		it("should return ERROR when DescribeTable fails", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["table1"] })
				.on(DescribeTableCommand)
				.rejects(new Error("Access Denied"));

			mockLambdaClient.on(ListEventSourceMappingsCommand).resolves({
				EventSourceMappings: []
			});

			const result = await checkDynamoDBStreamCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking table");
		});

		it("should return ERROR when ListEventSourceMappings fails", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["table1"] })
				.on(DescribeTableCommand)
				.resolves({ Table: mockTable1 });

			mockLambdaClient.on(ListEventSourceMappingsCommand).rejects(new Error("Lambda API Error"));

			const result = await checkDynamoDBStreamCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		});
	});
});
