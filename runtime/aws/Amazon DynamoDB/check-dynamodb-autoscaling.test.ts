// @ts-nocheck
import { DynamoDBClient, ListTablesCommand, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import {
	ApplicationAutoScalingClient,
	DescribeScalableTargetsCommand
} from "@aws-sdk/client-application-auto-scaling";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDynamoDBAutoScaling from "./check-dynamodb-autoscaling";

const mockDynamoDBClient = mockClient(DynamoDBClient);
const mockAutoScalingClient = mockClient(ApplicationAutoScalingClient);

const mockTable = {
	TableName: "test-table",
	TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/test-table"
};

describe("checkDynamoDBAutoScaling", () => {
	beforeEach(() => {
		mockDynamoDBClient.reset();
		mockAutoScalingClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for tables using on-demand capacity", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["test-table"] })
				.on(DescribeTableCommand)
				.resolves({
					Table: {
						...mockTable,
						BillingModeSummary: { BillingMode: "PAY_PER_REQUEST" }
					}
				});

			const result = await checkDynamoDBAutoScaling.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toContain("on-demand capacity mode");
		});

		it("should return PASS for provisioned tables with auto-scaling", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["test-table"] })
				.on(DescribeTableCommand)
				.resolves({
					Table: {
						...mockTable,
						BillingModeSummary: { BillingMode: "PROVISIONED" }
					}
				});

			mockAutoScalingClient.on(DescribeScalableTargetsCommand).resolves({
				ScalableTargets: [
					{
						ResourceId: "table/test-table",
						ScalableDimension: "dynamodb:table:ReadCapacityUnits"
					}
				]
			});

			const result = await checkDynamoDBAutoScaling.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toContain("has auto-scaling configured");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for provisioned tables without auto-scaling", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["test-table"] })
				.on(DescribeTableCommand)
				.resolves({
					Table: {
						...mockTable,
						BillingModeSummary: { BillingMode: "PROVISIONED" }
					}
				});

			mockAutoScalingClient.on(DescribeScalableTargetsCommand).resolves({ ScalableTargets: [] });

			const result = await checkDynamoDBAutoScaling.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("without auto-scaling");
		});

		it("should handle multiple tables with mixed compliance", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["table1", "table2"] })
				.on(DescribeTableCommand, { TableName: "table1" })
				.resolves({
					Table: {
						TableName: "table1",
						TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/table1",
						BillingModeSummary: { BillingMode: "PAY_PER_REQUEST" }
					}
				})
				.on(DescribeTableCommand, { TableName: "table2" })
				.resolves({
					Table: {
						TableName: "table2",
						TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/table2",
						BillingModeSummary: { BillingMode: "PROVISIONED" }
					}
				});

			mockAutoScalingClient.on(DescribeScalableTargetsCommand).resolves({ ScalableTargets: [] });

			const result = await checkDynamoDBAutoScaling.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases and Error Handling", () => {
		it("should return NOTAPPLICABLE when no tables exist", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: [] });

			const result = await checkDynamoDBAutoScaling.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toContain("No DynamoDB tables found");
		});

		it("should return ERROR when ListTables fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).rejects(new Error("API Error"));

			const result = await checkDynamoDBAutoScaling.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DynamoDB tables");
		});

		it("should handle errors for specific tables", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["test-table"] })
				.on(DescribeTableCommand)
				.rejects(new Error("Table not found"));

			const result = await checkDynamoDBAutoScaling.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking table");
		});
	});
});
