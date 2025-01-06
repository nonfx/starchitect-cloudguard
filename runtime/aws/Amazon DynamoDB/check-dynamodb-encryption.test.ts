// @ts-nocheck
import { DynamoDBClient, ListTablesCommand, DescribeTableCommand } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDynamoDBEncryption from "./check-dynamodb-encryption";

const mockDynamoDBClient = mockClient(DynamoDBClient);

const mockTable1 = {
	TableName: "test-table-1",
	TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/test-table-1",
	SSEDescription: {
		Status: "ENABLED"
	}
};

const mockTable2 = {
	TableName: "test-table-2",
	TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/test-table-2",
	SSEDescription: {
		Status: "DISABLED"
	}
};

describe("checkDynamoDBEncryption", () => {
	beforeEach(() => {
		mockDynamoDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when table has encryption enabled", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: [mockTable1.TableName] });
			mockDynamoDBClient.on(DescribeTableCommand).resolves({ Table: mockTable1 });

			const result = await checkDynamoDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockTable1.TableName);
			expect(result.checks[0].resourceArn).toBe(mockTable1.TableArn);
		});

		it("should return NOTAPPLICABLE when no tables exist", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: [] });

			const result = await checkDynamoDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DynamoDB tables found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when table has encryption disabled", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: [mockTable2.TableName] });
			mockDynamoDBClient.on(DescribeTableCommand).resolves({ Table: mockTable2 });

			const result = await checkDynamoDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"DynamoDB table does not have encryption at rest enabled"
			);
		});

		it("should handle mixed encryption configurations", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: [mockTable1.TableName, mockTable2.TableName] });
			mockDynamoDBClient
				.on(DescribeTableCommand, { TableName: mockTable1.TableName })
				.resolves({ Table: mockTable1 })
				.on(DescribeTableCommand, { TableName: mockTable2.TableName })
				.resolves({ Table: mockTable2 });

			const result = await checkDynamoDBEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListTables fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).rejects(new Error("Failed to list tables"));

			const result = await checkDynamoDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list tables");
		});

		it("should return ERROR when DescribeTable fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: [mockTable1.TableName] });
			mockDynamoDBClient.on(DescribeTableCommand).rejects(new Error("Access denied"));

			const result = await checkDynamoDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking table encryption");
		});

		it("should handle missing Table in DescribeTable response", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: [mockTable1.TableName] });
			mockDynamoDBClient.on(DescribeTableCommand).resolves({ Table: null });

			const result = await checkDynamoDBEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to retrieve table details");
		});
	});
});
