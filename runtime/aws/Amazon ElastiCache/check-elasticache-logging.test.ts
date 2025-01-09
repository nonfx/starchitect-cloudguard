// @ts-nocheck
import { ElastiCacheClient, DescribeReplicationGroupsCommand } from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheLoggingCompliance from "./check-elasticache-logging";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

const mockReplicationGroupWithLogging = {
	ReplicationGroupId: "test-replication-group-1",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:test-replication-group-1",
	LogDeliveryConfigurations: [
		{
			DestinationType: "cloudwatch-logs",
			DestinationDetails: { CloudWatchLogsDetails: { LogGroup: "test-log-group" } },
			LogFormat: "json"
		}
	]
};

const mockReplicationGroupWithoutLogging = {
	ReplicationGroupId: "test-replication-group-2",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:test-replication-group-2",
	LogDeliveryConfigurations: []
};

const mockReplicationGroupWithInvalidLogging = {
	ReplicationGroupId: "test-replication-group-3",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:test-replication-group-3",
	LogDeliveryConfigurations: [
		{
			DestinationType: "cloudwatch-logs",
			// Missing DestinationDetails
			LogFormat: "json"
		}
	]
};

describe("checkElastiCacheLoggingCompliance", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when audit logging is enabled with valid configuration", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockReplicationGroupWithLogging]
			});

			const result = await checkElastiCacheLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-replication-group-1");
			expect(result.checks[0].resourceArn).toBe(mockReplicationGroupWithLogging.ARN);
		});

		it("should return NOTAPPLICABLE when no replication groups exist", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: []
			});

			const result = await checkElastiCacheLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe(
				"No ElastiCache replication groups found in the region"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when audit logging is not enabled", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockReplicationGroupWithoutLogging]
			});

			const result = await checkElastiCacheLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Audit logging is not enabled for the replication group"
			);
		});

		it("should return FAIL when LogDeliveryConfigurations are invalid", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockReplicationGroupWithInvalidLogging]
			});

			const result = await checkElastiCacheLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Audit logging is not enabled for the replication group"
			);
		});

		it("should handle replication groups with missing IDs", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [{ LogDeliveryConfigurations: [] }] // Missing ReplicationGroupId
			});

			const result = await checkElastiCacheLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Replication group found without ID");
		});

		it("should handle mixed compliance results", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockReplicationGroupWithLogging, mockReplicationGroupWithoutLogging]
			});

			const result = await checkElastiCacheLoggingCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe(
				"Error checking ElastiCache replication groups: API Error"
			);
		});

		it("should handle undefined response", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({});

			const result = await checkElastiCacheLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});

		it("should handle unexpected response structure", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: undefined // Unexpected structure
			});

			const result = await checkElastiCacheLoggingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
