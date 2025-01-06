// @ts-nocheck
import {
	CloudTrailClient,
	GetTrailCommand,
	ListTrailsCommand,
	GetEventSelectorsCommand
} from "@aws-sdk/client-cloudtrail";
import { DynamoDBClient, ListTablesCommand } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDynamoDBAuditLogging from "./check-dynamodb-audit-logging";

const mockCloudTrailClient = mockClient(CloudTrailClient);
const mockDynamoDBClient = mockClient(DynamoDBClient);

const mockTables = {
	TableNames: ["table1", "table2"]
};

const mockTrails = {
	Trails: [
		{
			Name: "test-trail",
			TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail"
		}
	]
};

describe("checkDynamoDBAuditLogging", () => {
	beforeEach(() => {
		mockCloudTrailClient.reset();
		mockDynamoDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when DynamoDB audit logging is properly configured", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves(mockTables);
			mockCloudTrailClient.on(ListTrailsCommand).resolves(mockTrails);
			mockCloudTrailClient.on(GetTrailCommand).resolves({
				Trail: {
					Name: "test-trail"
				}
			});
			mockCloudTrailClient.on(GetEventSelectorsCommand).resolves({
				EventSelectors: [
					{
						DataResources: [
							{
								Type: "AWS::DynamoDB::Table"
							}
						]
					}
				]
			});

			const result = await checkDynamoDBAuditLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no DynamoDB tables exist", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({ TableNames: [] });

			const result = await checkDynamoDBAuditLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DynamoDB tables found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no CloudTrail trails exist", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves(mockTables);
			mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [] });

			const result = await checkDynamoDBAuditLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No CloudTrail trails configured for audit logging");
		});

		it("should return FAIL when CloudTrail exists but DynamoDB logging is not enabled", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves(mockTables);
			mockCloudTrailClient.on(ListTrailsCommand).resolves(mockTrails);
			mockCloudTrailClient.on(GetTrailCommand).resolves({
				Trail: {
					Name: "test-trail"
				}
			});
			mockCloudTrailClient.on(GetEventSelectorsCommand).resolves({
				EventSelectors: [
					{
						DataResources: [
							{
								Type: "AWS::S3::Object" // Different resource type
							}
						]
					}
				]
			});

			const result = await checkDynamoDBAuditLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"This DynamoDB table does not have audit logging enabled via CloudTrail"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListTables fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).rejects(new Error("Failed to list tables"));

			const result = await checkDynamoDBAuditLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list tables");
		});

		it("should handle GetTrail errors gracefully", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves(mockTables);
			mockCloudTrailClient.on(ListTrailsCommand).resolves(mockTrails);
			mockCloudTrailClient.on(GetTrailCommand).rejects(new Error("Failed to get trail"));

			const result = await checkDynamoDBAuditLogging.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
