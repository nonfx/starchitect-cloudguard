// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { ECSClient, ListClustersCommand, DescribeClustersCommand } from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkEcsContainerInsights from "./check-ecs-container-insights";

const mockEcsClient = mockClient(ECSClient);

const mockClusterArns = [
	"arn:aws:ecs:us-east-1:123456789012:cluster/cluster-1",
	"arn:aws:ecs:us-east-1:123456789012:cluster/cluster-2"
];

const mockClusterWithInsights = {
	clusterName: "cluster-1",
	clusterArn: mockClusterArns[0],
	settings: [
		{
			name: "containerInsights",
			value: "enabled"
		}
	]
};

const mockClusterWithoutInsights = {
	clusterName: "cluster-2",
	clusterArn: mockClusterArns[1],
	settings: [
		{
			name: "containerInsights",
			value: "disabled"
		}
	]
};

describe("checkEcsContainerInsights", () => {
	beforeEach(() => {
		mockEcsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Container Insights is enabled", async () => {
			mockEcsClient.on(ListClustersCommand).resolves({ clusterArns: [mockClusterArns[0]] });
			mockEcsClient.on(DescribeClustersCommand).resolves({ clusters: [mockClusterWithInsights] });

			const result = await checkEcsContainerInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockClusterArns[0]);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockEcsClient.on(ListClustersCommand).resolves({ clusterArns: [] });

			const result = await checkEcsContainerInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ECS clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Container Insights is disabled", async () => {
			mockEcsClient.on(ListClustersCommand).resolves({ clusterArns: [mockClusterArns[1]] });
			mockEcsClient
				.on(DescribeClustersCommand)
				.resolves({ clusters: [mockClusterWithoutInsights] });

			const result = await checkEcsContainerInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Container Insights is not enabled for this cluster");
		});

		it("should handle mixed compliance results", async () => {
			mockEcsClient.on(ListClustersCommand).resolves({ clusterArns: mockClusterArns });
			mockEcsClient
				.on(DescribeClustersCommand)
				.resolves({ clusters: [mockClusterWithInsights, mockClusterWithoutInsights] });

			const result = await checkEcsContainerInsights.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle clusters without name or ARN", async () => {
			mockEcsClient.on(ListClustersCommand).resolves({ clusterArns: [mockClusterArns[0]] });
			mockEcsClient.on(DescribeClustersCommand).resolves({ clusters: [{ settings: [] }] });

			const result = await checkEcsContainerInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without name or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListClusters fails", async () => {
			mockEcsClient.on(ListClustersCommand).rejects(new Error("Failed to list clusters"));

			const result = await checkEcsContainerInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list clusters");
		});

		it("should return ERROR when DescribeClusters fails", async () => {
			mockEcsClient.on(ListClustersCommand).resolves({ clusterArns: mockClusterArns });
			mockEcsClient.on(DescribeClustersCommand).rejects(new Error("Failed to describe clusters"));

			const result = await checkEcsContainerInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to describe clusters");
		});

		it("should handle missing clusters in describe response", async () => {
			mockEcsClient.on(ListClustersCommand).resolves({ clusterArns: mockClusterArns });
			mockEcsClient.on(DescribeClustersCommand).resolves({});

			const result = await checkEcsContainerInsights.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to get cluster details");
		});
	});
});
