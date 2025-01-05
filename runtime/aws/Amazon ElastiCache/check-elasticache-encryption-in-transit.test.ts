// @ts-nocheck
import { ElastiCacheClient, DescribeReplicationGroupsCommand } from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheEncryptionInTransit from "./check-elasticache-encryption-in-transit";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

const mockCompliantReplicationGroup = {
	ReplicationGroupId: "compliant-group",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:compliant-group",
	TransitEncryptionEnabled: true
};

const mockNonCompliantReplicationGroup = {
	ReplicationGroupId: "non-compliant-group",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:non-compliant-group",
	TransitEncryptionEnabled: false
};

describe("checkElastiCacheEncryptionInTransit", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for replication groups with encryption in transit enabled", async () => {
			mockElastiCacheClient
				.on(DescribeReplicationGroupsCommand)
				.resolves({ ReplicationGroups: [mockCompliantReplicationGroup], Marker: undefined });

			const result = await checkElastiCacheEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-group");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for non-compliant replication groups", async () => {
			mockElastiCacheClient
				.on(DescribeReplicationGroupsCommand)
				.resolves({ ReplicationGroups: [mockNonCompliantReplicationGroup], Marker: undefined });

			const result = await checkElastiCacheEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"ElastiCache ReplicationGroup does not have encryption in transit enabled"
			);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no replication groups exist", async () => {
			mockElastiCacheClient
				.on(DescribeReplicationGroupsCommand)
				.resolves({ ReplicationGroups: [], Marker: undefined });

			const result = await checkElastiCacheEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe(
				"No ElastiCache replication groups found in the region"
			);
		});

		it("should return ERROR when API calls fail", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheEncryptionInTransit.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain(
				"Error checking ElastiCache encryption: API Error"
			);
		});
	});

	describe("Pagination Handling", () => {
		it("should handle pagination for replication groups", async () => {
			mockElastiCacheClient
				.on(DescribeReplicationGroupsCommand)
				.resolvesOnce({ ReplicationGroups: [mockCompliantReplicationGroup], Marker: "token" })
				.resolvesOnce({ ReplicationGroups: [mockNonCompliantReplicationGroup], Marker: undefined });

			const result = await checkElastiCacheEncryptionInTransit.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
