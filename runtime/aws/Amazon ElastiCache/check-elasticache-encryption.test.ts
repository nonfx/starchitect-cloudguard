// @ts-nocheck
import { ElastiCacheClient, DescribeReplicationGroupsCommand } from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheEncryption from "./check-elasticache-encryption";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

const mockEncryptedGroup = {
	ReplicationGroupId: "encrypted-group",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:encrypted-group",
	AtRestEncryptionEnabled: true
};

const mockUnencryptedGroup = {
	ReplicationGroupId: "unencrypted-group",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:unencrypted-group",
	AtRestEncryptionEnabled: false
};

describe("checkElastiCacheEncryption", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when encryption at rest is enabled", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockEncryptedGroup]
			});

			const result = await checkElastiCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("encrypted-group");
			expect(result.checks[0].resourceArn).toBe(mockEncryptedGroup.ARN);
		});

		it("should return NOTAPPLICABLE when no replication groups exist", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: []
			});

			const result = await checkElastiCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe(
				"No ElastiCache replication groups found in the region"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when encryption at rest is disabled", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockUnencryptedGroup]
			});

			const result = await checkElastiCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"ElastiCache ReplicationGroup does not have encryption in transit enabled"
			);
		});

		it("should handle mixed encryption configurations", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockEncryptedGroup, mockUnencryptedGroup]
			});

			const result = await checkElastiCacheEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should return ERROR for malformed replication group data", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [{ AtRestEncryptionEnabled: true }] // Missing ID and ARN
			});

			const result = await checkElastiCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Replication group found without ID");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking ElastiCache encryption: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).rejects("String error");

			const result = await checkElastiCacheEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking ElastiCache encryption: String error");
		});
	});
});
