import { EC2Client, DescribeInstancesCommand, DescribeVpcEndpointsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkEc2VpcEndpointCompliance from "./aws_ec2_vpc_endpoint";

const mockEC2Client = mockClient(EC2Client);

const mockInstances = {
    Reservations: [
        {
            Instances: [
                {
                    InstanceId: "i-1234567890",
                    VpcId: "vpc-123"
                },
                {
                    InstanceId: "i-0987654321",
                    VpcId: "vpc-123"
                }
            ]
        },
        {
            Instances: [
                {
                    InstanceId: "i-abcdef1234",
                    VpcId: "vpc-456"
                }
            ]
        }
    ]
};

const mockVpcEndpoints = {
    VpcEndpoints: [
        {
            VpcEndpointId: "vpce-123",
            VpcId: "vpc-123",
            ServiceName: "com.amazonaws.us-east-1.ec2",
            VpcEndpointType: "Interface"
        }
    ]
};

describe("checkEc2VpcEndpointCompliance", () => {
    beforeEach(() => {
        mockEC2Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when VPC has EC2 endpoint configured", async () => {
            mockEC2Client
                .on(DescribeInstancesCommand)
                .resolves(mockInstances)
                .on(DescribeVpcEndpointsCommand)
                .resolves(mockVpcEndpoints);

            const result = await checkEc2VpcEndpointCompliance("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("VPC vpc-123");
        });

        it("should return NOTAPPLICABLE when no EC2 instances exist", async () => {
            mockEC2Client
                .on(DescribeInstancesCommand)
                .resolves({ Reservations: [] });

            const result = await checkEc2VpcEndpointCompliance("us-east-1");
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No EC2 instances found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when VPC has no EC2 endpoint", async () => {
            mockEC2Client
                .on(DescribeInstancesCommand)
                .resolves(mockInstances)
                .on(DescribeVpcEndpointsCommand)
                .resolves({ VpcEndpoints: [] });

            const result = await checkEc2VpcEndpointCompliance("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("no EC2 VPC endpoint");
        });

        it("should handle mixed compliance scenarios", async () => {
            mockEC2Client
                .on(DescribeInstancesCommand)
                .resolves(mockInstances)
                .on(DescribeVpcEndpointsCommand)
                .resolves({
                    VpcEndpoints: [
                        {
                            VpcEndpointId: "vpce-123",
                            VpcId: "vpc-123",
                            ServiceName: "com.amazonaws.us-east-1.ec2",
                            VpcEndpointType: "Interface"
                        }
                    ]
                });

            const result = await checkEc2VpcEndpointCompliance("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when DescribeInstances fails", async () => {
            mockEC2Client
                .on(DescribeInstancesCommand)
                .rejects(new Error("API Error"));

            const result = await checkEc2VpcEndpointCompliance("us-east-1");
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking EC2 VPC endpoints");
        });

        it("should return ERROR when DescribeVpcEndpoints fails", async () => {
            mockEC2Client
                .on(DescribeInstancesCommand)
                .resolves(mockInstances)
                .on(DescribeVpcEndpointsCommand)
                .rejects(new Error("API Error"));

            const result = await checkEc2VpcEndpointCompliance("us-east-1");
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking EC2 VPC endpoints");
        });
    });
});