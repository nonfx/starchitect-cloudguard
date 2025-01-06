// @ts-nocheck
import {
	DynamoDBClient,
	ListTablesCommand,
	DescribeContinuousBackupsCommand
} from "@aws-sdk/client-dynamodb";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDynamoDBPITR from "./check-dynamodb-pitr";

const mockDynamoDBClient = mockClient(DynamoDBClient);
const mockSTSClient = mockClient(STSClient);

const mockTable1 = {
	TableName: "test-table-1",
	TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/test-table-1",
	ContinuousBackupsDescription: {
		PointInTimeRecoveryDescription: {
			PointInTimeRecoveryStatus: "ENABLED",
			EarliestRestorableDateTime: new Date(),
			LatestRestorableDateTime: new Date()
		}
	}
};

const mockTable2 = {
	TableName: "test-table-2",
	TableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/test-table-2",
	ContinuousBackupsDescription: {
		PointInTimeRecoveryDescription: {
			PointInTimeRecoveryStatus: "DISABLED"
		}
	}
};

describe("checkDynamoDBPITR", () => {
	beforeEach(() => {
		mockDynamoDBClient.reset();
		mockSTSClient.reset();
		mockSTSClient.on(GetCallerIdentityCommand).resolves({ Account: "123456789012" });
	});

	describe("Compliant Resources", () => {
		it("should return PASS when PITR is enabled", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: ["test-table-1"] });
			mockDynamoDBClient.on(DescribeContinuousBackupsCommand).resolves(mockTable1);

			const result = await checkDynamoDBPITR.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-table-1");
			expect(result.checks[0].resourceArn).toBe(mockTable1.TableArn);
		});

		it("should return NOTAPPLICABLE when no tables exist", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: [] });

			const result = await checkDynamoDBPITR.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DynamoDB tables found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when PITR is disabled", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: ["test-table-2"] });
			mockDynamoDBClient.on(DescribeContinuousBackupsCommand).resolves(mockTable2);

			const result = await checkDynamoDBPITR.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Point-in-time recovery (PITR) is not enabled for this table"
			);
		});

		it("should handle mixed PITR configurations", async () => {
			mockDynamoDBClient
				.on(ListTablesCommand)
				.resolves({ TableNames: ["test-table-1", "test-table-2"] });
			mockDynamoDBClient
				.on(DescribeContinuousBackupsCommand, { TableName: "test-table-1" })
				.resolves(mockTable1)
				.on(DescribeContinuousBackupsCommand, { TableName: "test-table-2" })
				.resolves(mockTable2);

			const result = await checkDynamoDBPITR.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should handle ListTables API errors", async () => {
			mockDynamoDBClient.on(ListTablesCommand).rejects(new Error("API Error"));

			const result = await checkDynamoDBPITR.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DynamoDB tables");
		});

		it("should handle DescribeTable API errors", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: ["test-table-1"] });
			mockDynamoDBClient.on(DescribeContinuousBackupsCommand).rejects(new Error("Access Denied"));

			const result = await checkDynamoDBPITR.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking table PITR status");
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
			mockDynamoDBClient.on(DescribeContinuousBackupsCommand).resolves(mockTable1);

			const result = await checkDynamoDBPITR.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});
	});
});
