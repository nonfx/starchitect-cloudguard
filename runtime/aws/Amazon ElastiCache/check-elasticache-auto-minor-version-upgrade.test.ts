// @ts-nocheck
import { ElastiCacheClient, DescribeCacheClustersCommand } from "@aws-sdk/client-elasticache";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheAutoMinorVersionUpgrade from "./check-elasticache-auto-minor-version-upgrade";

const mockElastiCacheClient = mockClient(ElastiCacheClient);

const mockCompliantCluster = {
	CacheClusterId: "test-cluster-1",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-1",
	AutoMinorVersionUpgrade: true
};

const mockNonCompliantCluster = {
	CacheClusterId: "test-cluster-2",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-2",
	AutoMinorVersionUpgrade: false
};

describe("checkElastiCacheAutoMinorVersionUpgrade", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when auto minor version upgrade is enabled", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockCompliantCluster]
			});

			const result = await checkElastiCacheAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockCompliantCluster.ARN);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: []
			});

			const result = await checkElastiCacheAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ElastiCache clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when auto minor version upgrade is disabled", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockNonCompliantCluster]
			});

			const result = await checkElastiCacheAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Auto minor version upgrade is not enabled for the ElastiCache cluster"
			);
		});

		it("should handle mixed compliance results", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockCompliantCluster, mockNonCompliantCluster]
			});

			const result = await checkElastiCacheAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters without ID or ARN", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [{ AutoMinorVersionUpgrade: true }]
			});

			const result = await checkElastiCacheAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without ID or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking ElastiCache clusters: API Error");
		});
		it("should handle ThrottlingException errors", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).rejects({
				name: "ThrottlingException",
				message: "Rate exceeded"
			});

			const result = await checkElastiCacheAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking ElastiCache clusters: Rate exceeded");
		});
	});

	describe("Pagination Handling", () => {
		it("should handle pagination and process all clusters", async () => {
			mockElastiCacheClient
				.on(DescribeCacheClustersCommand)
				.resolvesOnce({
					CacheClusters: [mockCompliantCluster],
					Marker: "token1"
				})
				.resolvesOnce({
					CacheClusters: [mockNonCompliantCluster]
				});

			const result = await checkElastiCacheAutoMinorVersionUpgrade.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
