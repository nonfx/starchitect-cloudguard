//@ts-nocheck
import { ECSClient, ListServicesCommand, DescribeServicesCommand } from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEcsPublicIp from "./check-ecs-public-ip";

const mockEcsClient = mockClient(ECSClient);

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
			mockEcsClient.on(ListServicesCommand).resolves({ serviceArns: [mockServices[0].serviceArn] });
			mockEcsClient.on(DescribeServicesCommand).resolves({ services: [mockServices[0]] });

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("service-1");
		});

		it("should return NOTAPPLICABLE when no services exist", async () => {
			mockEcsClient.on(ListServicesCommand).resolves({ serviceArns: [] });

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ECS services found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when service has public IP enabled", async () => {
			mockEcsClient.on(ListServicesCommand).resolves({ serviceArns: [mockServices[1].serviceArn] });
			mockEcsClient.on(DescribeServicesCommand).resolves({ services: [mockServices[1]] });

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"ECS service has automatic public IP assignment enabled"
			);
		});

		it("should handle mixed compliance results", async () => {
			mockEcsClient
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
			mockEcsClient.on(ListServicesCommand).rejects(new Error("API Error"));

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ECS services");
		});

		it("should handle services without name or ARN", async () => {
			mockEcsClient.on(ListServicesCommand).resolves({ serviceArns: ["service-arn"] });
			mockEcsClient.on(DescribeServicesCommand).resolves({ services: [{}] });

			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Service found without name or ARN");
		});

		it("should handle pagination", async () => {
			const serviceArns = Array(15)
				.fill(null)
				.map((_, i) => `service-${i}`);
			mockEcsClient.on(ListServicesCommand).resolves({ serviceArns });
			mockEcsClient.on(DescribeServicesCommand).resolves({ services: [mockServices[0]] });

			// eslint-disable-next-line @typescript-eslint/no-unused-vars
			const result = await checkEcsPublicIp.execute("us-east-1");
			expect(mockEcsClient.calls()).toHaveLength(3); // 1 ListServices + 2 DescribeServices (batches of 10)
		});
	});
});
