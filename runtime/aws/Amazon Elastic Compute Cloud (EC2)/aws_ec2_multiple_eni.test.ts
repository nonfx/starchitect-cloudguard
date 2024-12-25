import { EC2Client, DescribeInstancesCommand, DescribeNetworkInterfacesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkEc2MultipleEniCompliance from "./aws_ec2_multiple_eni";

const mockEC2Client = mockClient(EC2Client);

const mockInstance = {
    InstanceId: "i-1234567890abcdef0",
    OwnerId: "123456789012"
};

describe("checkEc2MultipleEniCompliance", () => {
    beforeEach(() => {
        mockEC2Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when instance has single ENI", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{ Instances: [mockInstance] }]
            });

            mockEC2Client.on(DescribeNetworkInterfacesCommand).resolves({
                NetworkInterfaces: [{ NetworkInterfaceId: "eni-12345" }]
            });

            const result = await checkEc2MultipleEniCompliance.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe(mockInstance.InstanceId);
        });

        it("should return NOTAPPLICABLE when no instances exist", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: []
            });

            const result = await checkEc2MultipleEniCompliance.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No EC2 instances found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when instance has multiple ENIs", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{ Instances: [mockInstance] }]
            });

            mockEC2Client.on(DescribeNetworkInterfacesCommand).resolves({
                NetworkInterfaces: [
                    { NetworkInterfaceId: "eni-12345" },
                    { NetworkInterfaceId: "eni-67890" }
                ]
            });

            const result = await checkEc2MultipleEniCompliance.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("Instance has 2 ENIs attached");
        });

        it("should handle instances without InstanceId", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{ Instances: [{ OwnerId: "123456789012" }] }]
            });

            const result = await checkEc2MultipleEniCompliance.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Instance found without ID");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when DescribeInstances fails", async () => {
            mockEC2Client.on(DescribeInstancesCommand).rejects(
                new Error("Failed to describe instances")
            );

            const result = await checkEc2MultipleEniCompliance.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Failed to describe instances");
        });

        it("should return ERROR when DescribeNetworkInterfaces fails", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{ Instances: [mockInstance] }]
            });

            mockEC2Client.on(DescribeNetworkInterfacesCommand).rejects(
                new Error("Failed to describe network interfaces")
            );

            const result = await checkEc2MultipleEniCompliance.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Failed to describe network interfaces");
        });
    });

    describe("Multiple Instances", () => {
        it("should handle multiple instances with different ENI configurations", async () => {
            const instances = [
                { ...mockInstance, InstanceId: "i-111" },
                { ...mockInstance, InstanceId: "i-222" }
            ];

            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{ Instances: instances }]
            });

            mockEC2Client
                .on(DescribeNetworkInterfacesCommand, {
                    Filters: [{ Name: "attachment.instance-id", Values: ["i-111"] }]
                })
                .resolves({ NetworkInterfaces: [{ NetworkInterfaceId: "eni-1" }] })
                .on(DescribeNetworkInterfacesCommand, {
                    Filters: [{ Name: "attachment.instance-id", Values: ["i-222"] }]
                })
                .resolves({
                    NetworkInterfaces: [
                        { NetworkInterfaceId: "eni-2" },
                        { NetworkInterfaceId: "eni-3" }
                    ]
                });

            const result = await checkEc2MultipleEniCompliance.execute("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });
});