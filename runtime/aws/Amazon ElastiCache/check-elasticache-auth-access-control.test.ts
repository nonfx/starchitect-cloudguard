// @ts-nocheck
import { ElastiCacheClient, DescribeCacheClustersCommand } from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheAuthAccessControl from "./check-elasticache-auth-access-control";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

describe("checkElastiCacheAuthAccessControl", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when cluster has IAM authentication, encryption, and security groups enabled", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [
					{
						CacheClusterId: "test-cluster-1",
						AuthTokenEnabled: true,
						TransitEncryptionEnabled: true,
						AtRestEncryptionEnabled: true,
						SecurityGroups: [{ SecurityGroupId: "sg-12345" }]
					}
				]
			});

			const result = await checkElastiCacheAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
			expect(result.checks[0].message).toContain(
				"Authentication, encryption, and security group settings are properly configured"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when IAM authentication is disabled", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [
					{
						CacheClusterId: "test-cluster-1",
						AuthTokenEnabled: false, // IAM authentication disabled
						TransitEncryptionEnabled: true,
						AtRestEncryptionEnabled: true,
						SecurityGroups: [{ SecurityGroupId: "sg-12345" }]
					}
				]
			});

			const result = await checkElastiCacheAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("AUTH Enabled: false");
		});

		it("should return FAIL when transit encryption is disabled", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [
					{
						CacheClusterId: "test-cluster-1",
						AuthTokenEnabled: true,
						TransitEncryptionEnabled: false, // Transit encryption disabled
						AtRestEncryptionEnabled: true,
						SecurityGroups: [{ SecurityGroupId: "sg-12345" }]
					}
				]
			});

			const result = await checkElastiCacheAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("Transit Encryption: false");
		});

		it("should return FAIL when at-rest encryption is disabled", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [
					{
						CacheClusterId: "test-cluster-1",
						AuthTokenEnabled: true,
						TransitEncryptionEnabled: true,
						AtRestEncryptionEnabled: false, // At-rest encryption disabled
						SecurityGroups: [{ SecurityGroupId: "sg-12345" }]
					}
				]
			});

			const result = await checkElastiCacheAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("At Rest Encryption: false");
		});

		it("should return FAIL when no security groups are attached", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [
					{
						CacheClusterId: "test-cluster-1",
						AuthTokenEnabled: true,
						TransitEncryptionEnabled: true,
						AtRestEncryptionEnabled: true,
						SecurityGroups: [] // No security groups
					}
				]
			});

			const result = await checkElastiCacheAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("Security Groups: ");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: []
			});

			const result = await checkElastiCacheAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ElastiCache clusters found in the region");
		});

		it("should return ERROR when ElastiCache API call fails", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ElastiCache clusters");
		});
	});
});
