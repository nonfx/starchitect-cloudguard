//@ts-nocheck
import {
	ECSClient,
	ListServicesCommand,
	DescribeServicesCommand,
	ListClustersCommand
} from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEcsPublicIp from "./check-ecs-public-ip";

const mockEcsClient = mockClient(ECSClient);

const mockClusterArn = "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster";
const mockServices = [
	{
		serviceName: "service-1",
		serviceArn: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-1",
		networkConfiguration: {
			awsvpcConfiguration: {
				assignPublicIp: "DISABLED"
			}
		}
	},
	{
		serviceName: "service-2",
		serviceArn: "arn:aws:ecs:us-east-1:123456789012:service/cluster-1/service-2",
		networkConfiguration: {
			awsvpcConfiguration: {
				assignPublicIp: "ENABLED"
			}
		}
	}
];

describe("checkEcsPublicIp", () => {
	beforeEach(() => {
		mockEcsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when service has public IP disabled", async () => {
			mockEcsClient
				.on(ListClustersCommand)
				.resolves({ clusterArns: [mockClusterArn] })
				.on(ListServicesCommand)
				.resolves({ serviceArns: [mockServices[0].serviceArn] });
			mockEcsClient.on(DescribeServicesCommand).resolves({ services: [mockServices[0]] });

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("service-1");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when service has public IP enabled", async () => {
			mockEcsClient
				.on(ListClustersCommand)
				.resolves({ clusterArns: [mockClusterArn] })
				.on(ListServicesCommand)
				.resolves({ serviceArns: [mockServices[1].serviceArn] });
			mockEcsClient.on(DescribeServicesCommand).resolves({ services: [mockServices[1]] });

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"ECS service has automatic public IP assignment enabled"
			);
		});

		it("should handle mixed compliance results", async () => {
			mockEcsClient
				.on(ListClustersCommand)
				.resolves({ clusterArns: [mockClusterArn] })
				.on(ListServicesCommand)
				.resolves({ serviceArns: mockServices.map(s => s.serviceArn) });
			mockEcsClient.on(DescribeServicesCommand).resolves({ services: mockServices });

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListServices fails", async () => {
			mockEcsClient.on(ListClustersCommand).rejects(new Error("API Error"));

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ECS services");
		});

		it("should handle services without name or ARN", async () => {
			mockEcsClient
				.on(ListClustersCommand)
				.resolves({ clusterArns: [mockClusterArn] })
				.on(ListServicesCommand)
				.resolves({ serviceArns: ["service-arn"] });
			mockEcsClient.on(DescribeServicesCommand).resolves({ services: [{}] });

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Service found without name or ARN");
		});

		it("should handle pagination", async () => {
			// Mock cluster pagination
			mockEcsClient
				.on(ListClustersCommand)
				.resolvesOnce({ clusterArns: [mockClusterArn], nextToken: "cluster-token" })
				.resolvesOnce({ clusterArns: [`${mockClusterArn}-2`] });

			// Mock service pagination for first cluster
			mockEcsClient
				.on(ListServicesCommand)
				.resolvesOnce({
					serviceArns: Array(10)
						.fill(null)
						.map((_, i) => `service-${i}`),
					nextToken: "service-token"
				})
				.resolvesOnce({
					serviceArns: Array(5)
						.fill(null)
						.map((_, i) => `service-${i + 10}`)
				});

			// Mock service descriptions
			mockEcsClient.on(DescribeServicesCommand).resolves({ services: [mockServices[0]] });

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(mockEcsClient.calls()).toHaveLength(7);
		});
	});
});
