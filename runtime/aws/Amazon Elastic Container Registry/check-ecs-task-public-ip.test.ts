// @ts-nocheck
import { ECSClient, ListClustersCommand, ListServicesCommand, DescribeServicesCommand } from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEcsTaskPublicIp from "./check-ecs-task-public-ip";

const mockEcsClient = mockClient(ECSClient);

const mockClusterArn = "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster";
const mockServiceArn = "arn:aws:ecs:us-east-1:123456789012:service/test-service";

describe("checkEcsTaskPublicIp", () => {
    beforeEach(() => {
        mockEcsClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when public IP assignment is disabled", async () => {
            mockEcsClient
                .on(ListClustersCommand)
                .resolves({ clusterArns: [mockClusterArn] })
                .on(ListServicesCommand)
                .resolves({ serviceArns: [mockServiceArn] })
                .on(DescribeServicesCommand)
                .resolves({
                    services: [{
                        serviceName: "test-service",
                        serviceArn: mockServiceArn,
                        networkConfiguration: {
                            awsvpcConfiguration: {
                                assignPublicIp: "DISABLED"
                            }
                        }
                    }]
                });

            const result = await checkEcsTaskPublicIp.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("test-service");
        });

        it("should return NOTAPPLICABLE when no clusters exist", async () => {
            mockEcsClient
                .on(ListClustersCommand)
                .resolves({ clusterArns: [] });

            const result = await checkEcsTaskPublicIp.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No ECS clusters found in the region");
        });

        it("should return NOTAPPLICABLE when service doesn't use awsvpc mode", async () => {
            mockEcsClient
                .on(ListClustersCommand)
                .resolves({ clusterArns: [mockClusterArn] })
                .on(ListServicesCommand)
                .resolves({ serviceArns: [mockServiceArn] })
                .on(DescribeServicesCommand)
                .resolves({
                    services: [{
                        serviceName: "test-service",
                        serviceArn: mockServiceArn,
                        networkConfiguration: null
                    }]
                });

            const result = await checkEcsTaskPublicIp.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("Service does not use awsvpc network mode");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when public IP assignment is enabled", async () => {
            mockEcsClient
                .on(ListClustersCommand)
                .resolves({ clusterArns: [mockClusterArn] })
                .on(ListServicesCommand)
                .resolves({ serviceArns: [mockServiceArn] })
                .on(DescribeServicesCommand)
                .resolves({
                    services: [{
                        serviceName: "test-service",
                        serviceArn: mockServiceArn,
                        networkConfiguration: {
                            awsvpcConfiguration: {
                                assignPublicIp: "ENABLED"
                            }
                        }
                    }]
                });

            const result = await checkEcsTaskPublicIp.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Service automatically assigns public IP addresses");
        });

        it("should handle multiple services with mixed compliance", async () => {
            mockEcsClient
                .on(ListClustersCommand)
                .resolves({ clusterArns: [mockClusterArn] })
                .on(ListServicesCommand)
                .resolves({ serviceArns: [mockServiceArn, `${mockServiceArn}-2`] })
                .on(DescribeServicesCommand)
                .resolves({
                    services: [
                        {
                            serviceName: "test-service-1",
                            serviceArn: mockServiceArn,
                            networkConfiguration: {
                                awsvpcConfiguration: { assignPublicIp: "ENABLED" }
                            }
                        },
                        {
                            serviceName: "test-service-2",
                            serviceArn: `${mockServiceArn}-2`,
                            networkConfiguration: {
                                awsvpcConfiguration: { assignPublicIp: "DISABLED" }
                            }
                        }
                    ]
                });

            const result = await checkEcsTaskPublicIp.execute("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockEcsClient
                .on(ListClustersCommand)
                .rejects(new Error("API Error"));

            const result = await checkEcsTaskPublicIp.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking ECS services");
        });

        it("should handle services without name or ARN", async () => {
            mockEcsClient
                .on(ListClustersCommand)
                .resolves({ clusterArns: [mockClusterArn] })
                .on(ListServicesCommand)
                .resolves({ serviceArns: [mockServiceArn] })
                .on(DescribeServicesCommand)
                .resolves({
                    services: [{ }]
                });

            const result = await checkEcsTaskPublicIp.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Service found without name or ARN");
        });
    });
});