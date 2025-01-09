// @ts-nocheck
import { ElastiCacheClient, DescribeReplicationGroupsCommand } from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheAutoFailover from "./check-elasticache-auto-failover";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

const mockReplicationGroup = {
	ReplicationGroupId: "test-group-1",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:test-group-1",
	AutomaticFailover: "enabled"
};

const mockReplicationGroupNoFailover = {
	ReplicationGroupId: "test-group-2",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:test-group-2",
	AutomaticFailover: "disabled"
};

describe("checkElastiCacheAutoFailover", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when automatic failover is enabled", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockReplicationGroup]
			});

			const result = await checkElastiCacheAutoFailover.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-group-1");
			expect(result.checks[0].resourceArn).toBe(mockReplicationGroup.ARN);
		});

		it("should return NOTAPPLICABLE when no replication groups exist", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: []
			});

			const result = await checkElastiCacheAutoFailover.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe(
				"No ElastiCache replication groups found in the region"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when automatic failover is disabled", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockReplicationGroupNoFailover]
			});

			const result = await checkElastiCacheAutoFailover.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Automatic failover is not enabled for this replication group"
			);
		});

		it("should handle mixed compliance states", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockReplicationGroup, mockReplicationGroupNoFailover]
			});

			const result = await checkElastiCacheAutoFailover.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should return ERROR for malformed replication group", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [{ ReplicationGroupId: null, ARN: null }]
			});

			const result = await checkElastiCacheAutoFailover.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Replication group found without ID or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheAutoFailover.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ElastiCache replication groups");
		});

		it("should handle undefined ReplicationGroups response", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({});

			const result = await checkElastiCacheAutoFailover.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
