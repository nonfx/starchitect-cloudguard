// @ts-nocheck
import { ElastiCacheClient, DescribeCacheClustersCommand } from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheAutomaticUpdates from "./check-elasticache-automatic-updates";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

const mockClusterWithAutoUpdate = {
	CacheClusterId: "test-cluster-1",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-1",
	AutoMinorVersionUpgrade: true
};

const mockClusterWithoutAutoUpdate = {
	CacheClusterId: "test-cluster-2",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-2",
	AutoMinorVersionUpgrade: false
};

describe("checkElastiCacheAutomaticUpdates", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when automatic updates are enabled", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockClusterWithAutoUpdate]
			});

			const result = await checkElastiCacheAutomaticUpdates.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockClusterWithAutoUpdate.ARN);
		});

		it("should handle multiple compliant clusters", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockClusterWithAutoUpdate, mockClusterWithAutoUpdate]
			});

			const result = await checkElastiCacheAutomaticUpdates.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when automatic updates are disabled", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockClusterWithoutAutoUpdate]
			});

			const result = await checkElastiCacheAutomaticUpdates.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Automatic minor version upgrades are not enabled for this cluster"
			);
		});

		it("should handle mixed compliance status", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockClusterWithAutoUpdate, mockClusterWithoutAutoUpdate]
			});

			const result = await checkElastiCacheAutomaticUpdates.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: []
			});

			const result = await checkElastiCacheAutomaticUpdates.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ElastiCache clusters found in the region");
		});

		it("should handle clusters without CacheClusterId", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [{ AutoMinorVersionUpgrade: true }]
			});

			const result = await checkElastiCacheAutomaticUpdates.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without ID");
		});
	});

	describe("Pagination", () => {
		it("should handle paginated results", async () => {
			mockElastiCacheClient
				.on(DescribeCacheClustersCommand)
				.resolvesOnce({
					CacheClusters: [mockClusterWithAutoUpdate],
					Marker: "nextPage"
				})
				.resolvesOnce({
					CacheClusters: [mockClusterWithoutAutoUpdate]
				});

			const result = await checkElastiCacheAutomaticUpdates.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheAutomaticUpdates.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking ElastiCache clusters: API Error");
		});
	});
});
