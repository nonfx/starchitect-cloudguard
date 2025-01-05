// @ts-nocheck
import { ElastiCacheClient, DescribeReplicationGroupsCommand } from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheSecureAccess from "./check-elasticache-secure-access";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

const mockCompliantGroup = {
	ReplicationGroupId: "secure-group",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:secure-group",
	AuthTokenEnabled: true,
	TransitEncryptionEnabled: true
};

const mockNonCompliantGroup = {
	ReplicationGroupId: "insecure-group",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:insecure-group",
	AuthTokenEnabled: false,
	TransitEncryptionEnabled: false
};

describe("checkElastiCacheSecureAccess", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when replication group has both auth token and encryption enabled", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockCompliantGroup]
			});

			const result = await checkElastiCacheSecureAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("secure-group");
			expect(result.checks[0].resourceArn).toBe(mockCompliantGroup.ARN);
			expect(result.checks[0].message).toBeUndefined();
		});

		it("should return NOTAPPLICABLE when no replication groups exist", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: []
			});

			const result = await checkElastiCacheSecureAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe(
				"No ElastiCache replication groups found in the region"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when both auth token and encryption are disabled", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [mockNonCompliantGroup]
			});

			const result = await checkElastiCacheSecureAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Authentication is not enabled; Transit encryption is not enabled"
			);
		});

		it("should return FAIL when only auth token is disabled", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [
					{
						...mockNonCompliantGroup,
						TransitEncryptionEnabled: true
					}
				]
			});

			const result = await checkElastiCacheSecureAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Authentication is not enabled");
		});

		it("should return FAIL when only encryption is disabled", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [
					{
						...mockNonCompliantGroup,
						AuthTokenEnabled: true
					}
				]
			});

			const result = await checkElastiCacheSecureAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Transit encryption is not enabled");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheSecureAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe(
				"Error checking ElastiCache replication groups: API Error"
			);
		});

		it("should return ERROR for malformed replication group data", async () => {
			mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
				ReplicationGroups: [{}] // Missing required fields
			});

			const result = await checkElastiCacheSecureAccess.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Replication group found without ID or ARN");
		});
	});

	it("should handle multiple replication groups with mixed compliance", async () => {
		mockElastiCacheClient.on(DescribeReplicationGroupsCommand).resolves({
			ReplicationGroups: [mockCompliantGroup, mockNonCompliantGroup]
		});

		const result = await checkElastiCacheSecureAccess.execute("us-east-1");
		expect(result.checks).toHaveLength(2);
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
	});
});
