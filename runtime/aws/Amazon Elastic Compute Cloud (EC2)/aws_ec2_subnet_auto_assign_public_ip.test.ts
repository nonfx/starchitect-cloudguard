import { EC2Client, DescribeSubnetsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkSubnetAutoAssignPublicIp from "./aws_ec2_subnet_auto_assign_public_ip";

const mockEC2Client = mockClient(EC2Client);

const mockCompliantSubnet = {
    SubnetId: "subnet-12345",
    OwnerId: "123456789012",
    MapPublicIpOnLaunch: false,
    Tags: [{ Key: "Name", Value: "compliant-subnet" }]
};

const mockNonCompliantSubnet = {
    SubnetId: "subnet-67890",
    OwnerId: "123456789012",
    MapPublicIpOnLaunch: true,
    Tags: [{ Key: "Name", Value: "non-compliant-subnet" }]
};

describe("checkSubnetAutoAssignPublicIp", () => {
    beforeEach(() => {
        mockEC2Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when subnet does not auto-assign public IPs", async () => {
            mockEC2Client.on(DescribeSubnetsCommand).resolves({
                Subnets: [mockCompliantSubnet]
            });

            const result = await checkSubnetAutoAssignPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("compliant-subnet");
        });

        it("should handle multiple compliant subnets", async () => {
            mockEC2Client.on(DescribeSubnetsCommand).resolves({
                Subnets: [mockCompliantSubnet, { ...mockCompliantSubnet, SubnetId: "subnet-abcde" }]
            });

            const result = await checkSubnetAutoAssignPublicIp("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when subnet auto-assigns public IPs", async () => {
            mockEC2Client.on(DescribeSubnetsCommand).resolves({
                Subnets: [mockNonCompliantSubnet]
            });

            const result = await checkSubnetAutoAssignPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Subnet automatically assigns public IP addresses");
        });

        it("should handle mixed compliance scenarios", async () => {
            mockEC2Client.on(DescribeSubnetsCommand).resolves({
                Subnets: [mockCompliantSubnet, mockNonCompliantSubnet]
            });

            const result = await checkSubnetAutoAssignPublicIp("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });

        it("should handle subnet without SubnetId", async () => {
            mockEC2Client.on(DescribeSubnetsCommand).resolves({
                Subnets: [{ MapPublicIpOnLaunch: true }]
            });

            const result = await checkSubnetAutoAssignPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Subnet found without Subnet ID");
        });
    });

    describe("Edge Cases", () => {
        it("should return NOTAPPLICABLE when no subnets exist", async () => {
            mockEC2Client.on(DescribeSubnetsCommand).resolves({
                Subnets: []
            });

            const result = await checkSubnetAutoAssignPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No subnets found in the region");
        });

        it("should handle undefined Subnets in response", async () => {
            mockEC2Client.on(DescribeSubnetsCommand).resolves({});

            const result = await checkSubnetAutoAssignPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockEC2Client.on(DescribeSubnetsCommand).rejects(new Error("API Error"));

            const result = await checkSubnetAutoAssignPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking subnets: API Error");
        });

        it("should handle non-Error exceptions", async () => {
            mockEC2Client.on(DescribeSubnetsCommand).rejects("String error");

            const result = await checkSubnetAutoAssignPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking subnets: String error");
        });
    });
});