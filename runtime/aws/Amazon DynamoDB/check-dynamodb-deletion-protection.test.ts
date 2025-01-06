// @ts-nocheck
import { DynamoDBClient, ListTablesCommand, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDynamoDBDeletionProtection from "./check-dynamodb-deletion-protection";

const mockDynamoDBClient = mockClient(DynamoDBClient);

const mockTable1 = {
	TableName: "test-table-1",
	TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/test-table-1",
	DeletionProtectionEnabled: true
};

const mockTable2 = {
	TableName: "test-table-2",
	TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/test-table-2",
	DeletionProtectionEnabled: false
};

describe("checkDynamoDBDeletionProtection", () => {
	beforeEach(() => {
		mockDynamoDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when deletion protection is enabled", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: ["test-table-1"] });
			mockDynamoDBClient.on(DescribeTableCommand).resolves({ Table: mockTable1 });

			const result = await checkDynamoDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-table-1");
			expect(result.checks[0].resourceArn).toBe(mockTable1.TableArn);
		});

		it("should return NOTAPPLICABLE when no tables exist", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: [] });

			const result = await checkDynamoDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DynamoDB tables found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when deletion protection is disabled", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: ["test-table-2"] });
			mockDynamoDBClient.on(DescribeTableCommand).resolves({ Table: mockTable2 });

			const result = await checkDynamoDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"DynamoDB table does not have deletion protection enabled"
			);
		});

		it("should handle mixed compliance results", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["test-table-1", "test-table-2"] });
			mockDynamoDBClient
				.on(DescribeTableCommand, { TableName: "test-table-1" })
				.resolves({ Table: mockTable1 })
				.on(DescribeTableCommand, { TableName: "test-table-2" })
				.resolves({ Table: mockTable2 });

			const result = await checkDynamoDBDeletionProtection.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should handle ListTables API errors", async () => {
			mockDynamoDBClient.on(ListTablesCommand).rejects(new Error("API Error"));

			const result = await checkDynamoDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DynamoDB tables");
		});

		it("should handle DescribeTable API errors", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: ["test-table-1"] });
			mockDynamoDBClient.on(DescribeTableCommand).rejects(new Error("Access Denied"));

			const result = await checkDynamoDBDeletionProtection.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking table");
		});

		it("should handle pagination", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolvesOnce({
					TableNames: ["test-table-1"],
					LastEvaluatedTableName: "test-table-1"
				})
				.resolvesOnce({
					TableNames: ["test-table-2"]
				});
			mockDynamoDBClient
				.on(DescribeTableCommand, { TableName: "test-table-1" })
				.resolves({ Table: mockTable1 })
				.on(DescribeTableCommand, { TableName: "test-table-2" })
				.resolves({ Table: mockTable2 });

			const result = await checkDynamoDBDeletionProtection.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});
	});
});
