// @ts-nocheck
import { ElastiCacheClient, DescribeCacheClustersCommand } from "@aws-sdk/client-elasticache";
import { CloudWatchClient, ListMetricsCommand } from "@aws-sdk/client-cloudwatch";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElastiCacheMonitoring from "./check-elasticache-monitoring";

const mockElastiCacheClient = mockClient(ElastiCacheClient);
const mockCloudWatchClient = mockClient(CloudWatchClient);

const mockCompliantCluster = {
	CacheClusterId: "test-cluster-1",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-1",
	LogDeliveryConfigurations: [
		{
			DestinationType: "cloudwatch-logs",
			Destination: "loggroup1",
			LogFormat: "json",
			LogType: "slow-log"
		}
	]
};

const mockNonCompliantCluster = {
	CacheClusterId: "test-cluster-2",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-2",
	LogDeliveryConfigurations: []
};

const mockClusterWithMetricsOnly = {
	CacheClusterId: "test-cluster-3",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-3",
	LogDeliveryConfigurations: []
};

const mockClusterWithLogsOnly = {
	CacheClusterId: "test-cluster-4",
	ARN: "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster-4",
	LogDeliveryConfigurations: [
		{
			DestinationType: "cloudwatch-logs",
			Destination: "loggroup1",
			LogFormat: "json",
			LogType: "slow-log"
		}
	]
};

describe("checkElastiCacheMonitoring", () => {
	beforeEach(() => {
		mockElastiCacheClient.reset();
		mockCloudWatchClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when cluster has both CloudWatch logs and Enhanced Monitoring metrics enabled", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockCompliantCluster]
			});
			mockCloudWatchClient.on(ListMetricsCommand).resolves({
				Metrics: [{ MetricName: "CPUUtilization" }]
			});

			const result = await checkElastiCacheMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockCompliantCluster.ARN);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when cluster has no CloudWatch logs", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockNonCompliantCluster]
			});
			mockCloudWatchClient.on(ListMetricsCommand).resolves({
				Metrics: []
			});

			const result = await checkElastiCacheMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"ElastiCache cluster does not have Enhanced Monitoring metrics enabled"
			);
		});

		it("should return FAIL when cluster has no Enhanced Monitoring metrics", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [mockClusterWithLogsOnly]
			});
			mockCloudWatchClient.on(ListMetricsCommand).resolves({
				Metrics: []
			});

			const result = await checkElastiCacheMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"ElastiCache cluster does not have Enhanced Monitoring metrics enabled"
			);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: []
			});

			const result = await checkElastiCacheMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ElastiCache clusters found in the region");
		});

		it("should handle clusters without CacheClusterId", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).resolves({
				CacheClusters: [{ LogDeliveryConfigurations: [] }]
			});

			const result = await checkElastiCacheMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without ID");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockElastiCacheClient.on(DescribeCacheClustersCommand).rejects(new Error("API Error"));

			const result = await checkElastiCacheMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ElastiCache clusters");
		});
	});
});
