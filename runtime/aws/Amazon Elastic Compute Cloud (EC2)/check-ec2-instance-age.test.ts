// @ts-nocheck
import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkEc2InstanceAge from "./check-ec2-instance-age";

const mockEC2Client = mockClient(EC2Client);

const createMockInstance = (instanceId: string, launchTime: Date) => ({
    InstanceId: instanceId,
    LaunchTime: launchTime
});

describe("checkEc2InstanceAge", () => {
    beforeEach(() => {
        mockEC2Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for instances less than 180 days old", async () => {
            const recentDate = new Date();
            recentDate.setDate(recentDate.getDate() - 30); // 30 days old

            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{
                    Instances: [
                        createMockInstance("i-123456789", recentDate)
                    ]
                }]
            });

            const result = await checkEc2InstanceAge("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("i-123456789");
        });

        it("should return NOTAPPLICABLE when no instances exist", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: []
            });

            const result = await checkEc2InstanceAge("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No running EC2 instances found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for instances older than 180 days", async () => {
            const oldDate = new Date();
            oldDate.setDate(oldDate.getDate() - 200); // 200 days old

            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{
                    Instances: [
                        createMockInstance("i-987654321", oldDate)
                    ]
                }]
            });

            const result = await checkEc2InstanceAge("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("200 days old");
        });

        it("should return ERROR for instances with missing data", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{
                    Instances: [{
                        InstanceId: null,
                        LaunchTime: null
                    }]
                }]
            });

            const result = await checkEc2InstanceAge("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Instance missing ID or launch time");
        });
    });

    describe("Pagination and Error Handling", () => {
        it("should handle pagination correctly", async () => {
            const recentDate = new Date();
            recentDate.setDate(recentDate.getDate() - 30);
            const oldDate = new Date();
            oldDate.setDate(oldDate.getDate() - 200);

            mockEC2Client
                .on(DescribeInstancesCommand)
                .resolvesOnce({
                    Reservations: [{
                        Instances: [createMockInstance("i-123", recentDate)]
                    }],
                    NextToken: "token1"
                })
                .resolvesOnce({
                    Reservations: [{
                        Instances: [createMockInstance("i-456", oldDate)]
                    }]
                });

            const result = await checkEc2InstanceAge("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });

        it("should handle API errors gracefully", async () => {
            mockEC2Client.on(DescribeInstancesCommand).rejects(
                new Error("API Error")
            );

            const result = await checkEc2InstanceAge("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking EC2 instances");
        });
    });
});