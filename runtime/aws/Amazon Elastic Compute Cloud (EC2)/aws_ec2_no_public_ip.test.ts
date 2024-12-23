import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkEc2PublicIpCompliance from "./aws_ec2_no_public_ip";

const mockEC2Client = mockClient(EC2Client);

const mockPrivateInstance = {
    InstanceId: "i-private123",
    OwnerId: "123456789012",
    PublicIpAddress: undefined,
    NetworkInterfaces: [
        {
            Association: {
                PublicIp: undefined
            }
        }
    ]
};

const mockPublicInstance = {
    InstanceId: "i-public456",
    OwnerId: "123456789012",
    PublicIpAddress: "203.0.113.1",
    NetworkInterfaces: []
};

const mockInstanceWithPublicNetworkInterface = {
    InstanceId: "i-public789",
    OwnerId: "123456789012",
    PublicIpAddress: undefined,
    NetworkInterfaces: [
        {
            Association: {
                PublicIp: "203.0.113.2"
            }
        }
    ]
};

describe("checkEc2PublicIpCompliance", () => {
    beforeEach(() => {
        mockEC2Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for instances without public IPs", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{ Instances: [mockPrivateInstance] }]
            });

            const result = await checkEc2PublicIpCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("i-private123");
        });

        it("should return NOTAPPLICABLE when no instances exist", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: []
            });

            const result = await checkEc2PublicIpCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No EC2 instances found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for instances with public IPs", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{ Instances: [mockPublicInstance] }]
            });

            const result = await checkEc2PublicIpCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("EC2 instance has a public IPv4 address configured");
        });

        it("should return FAIL for instances with public network interfaces", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{ Instances: [mockInstanceWithPublicNetworkInterface] }]
            });

            const result = await checkEc2PublicIpCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("EC2 instance has a public IPv4 address configured");
        });

        it("should handle mixed compliance scenarios", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{ 
                    Instances: [
                        mockPrivateInstance,
                        mockPublicInstance,
                        mockInstanceWithPublicNetworkInterface
                    ] 
                }]
            });

            const result = await checkEc2PublicIpCompliance("us-east-1");
            expect(result.checks).toHaveLength(3);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[2].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockEC2Client.on(DescribeInstancesCommand).rejects(new Error("API Error"));

            const result = await checkEc2PublicIpCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Error checking EC2 instances: API Error");
        });

        it("should handle instances without IDs", async () => {
            mockEC2Client.on(DescribeInstancesCommand).resolves({
                Reservations: [{ 
                    Instances: [{ 
                        InstanceId: undefined,
                        PublicIpAddress: "203.0.113.1" 
                    }] 
                }]
            });

            const result = await checkEc2PublicIpCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Instance found without ID");
        });
    });

    describe("Pagination", () => {
        it("should handle paginated results", async () => {
            mockEC2Client
                .on(DescribeInstancesCommand)
                .resolvesOnce({
                    Reservations: [{ Instances: [mockPrivateInstance] }],
                    NextToken: "token1"
                })
                .resolvesOnce({
                    Reservations: [{ Instances: [mockPublicInstance] }]
                });

            const result = await checkEc2PublicIpCompliance("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });
});