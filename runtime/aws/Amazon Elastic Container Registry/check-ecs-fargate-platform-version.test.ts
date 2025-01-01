// @ts-nocheck
import { ECSClient, ListServicesCommand, DescribeServicesCommand } from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEcsFargatePlatformVersion from "./check-ecs-fargate-platform-version";

const mockECSClient = mockClient(ECSClient);

const mockFargateService = (name: string, platformVersion: string) => ({
    serviceName: name,
    serviceArn: `arn:aws:ecs:us-east-1:123456789012:service/${name}`,
    launchType: "FARGATE",
    platformVersion
});

describe("checkEcsFargatePlatformVersion", () => {
    beforeEach(() => {
        mockECSClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for services running latest Linux version", async () => {
            mockECSClient
                .on(ListServicesCommand)
                .resolves({ serviceArns: ["service1", "service2"] });
            mockECSClient.on(DescribeServicesCommand).resolves({
                services: [
                    mockFargateService("service1", "1.4.0"),
                    mockFargateService("service2", "LATEST")
                ]
            });

            const result = await checkEcsFargatePlatformVersion.execute();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
        });

        it("should return PASS for services running latest Windows version", async () => {
            mockECSClient
                .on(ListServicesCommand)
                .resolves({ serviceArns: ["windows-service"] });
            mockECSClient.on(DescribeServicesCommand).resolves({
                services: [mockFargateService("windows-service", "1.0.0")]
            });

            const result = await checkEcsFargatePlatformVersion.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
        });

        it("should return NOTAPPLICABLE when no services exist", async () => {
            mockECSClient.on(ListServicesCommand).resolves({ serviceArns: [] });

            const result = await checkEcsFargatePlatformVersion.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No ECS services found in the cluster");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for services running older versions", async () => {
            mockECSClient
                .on(ListServicesCommand)
                .resolves({ serviceArns: ["old-service"] });
            mockECSClient.on(DescribeServicesCommand).resolves({
                services: [mockFargateService("old-service", "1.3.0")]
            });

            const result = await checkEcsFargatePlatformVersion.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("1.3.0");
        });

        it("should handle mixed compliant and non-compliant services", async () => {
            mockECSClient
                .on(ListServicesCommand)
                .resolves({ serviceArns: ["service1", "service2"] });
            mockECSClient.on(DescribeServicesCommand).resolves({
                services: [
                    mockFargateService("service1", "1.4.0"),
                    mockFargateService("service2", "1.2.0")
                ]
            });

            const result = await checkEcsFargatePlatformVersion.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });

        it("should ignore non-Fargate services", async () => {
            mockECSClient
                .on(ListServicesCommand)
                .resolves({ serviceArns: ["ec2-service"] });
            mockECSClient.on(DescribeServicesCommand).resolves({
                services: [{
                    serviceName: "ec2-service",
                    serviceArn: "arn:aws:ecs:us-east-1:123456789012:service/ec2-service",
                    launchType: "EC2"
                }]
            });

            const result = await checkEcsFargatePlatformVersion.execute();
            expect(result.checks).toHaveLength(0);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when ListServices fails", async () => {
            mockECSClient
                .on(ListServicesCommand)
                .rejects(new Error("Failed to list services"));

            const result = await checkEcsFargatePlatformVersion.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Failed to list services");
        });

        it("should return ERROR when DescribeServices fails", async () => {
            mockECSClient
                .on(ListServicesCommand)
                .resolves({ serviceArns: ["service1"] });
            mockECSClient
                .on(DescribeServicesCommand)
                .rejects(new Error("Failed to describe services"));

            const result = await checkEcsFargatePlatformVersion.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Failed to describe services");
        });
    });
});