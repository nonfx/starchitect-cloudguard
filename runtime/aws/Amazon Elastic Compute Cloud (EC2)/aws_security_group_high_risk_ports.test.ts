import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkSecurityGroupHighRiskPorts from "./aws_security_group_high_risk_ports";

const mockEC2Client = mockClient(EC2Client);

const mockCompliantSG = {
    GroupId: "sg-compliant",
    GroupName: "compliant-sg",
    OwnerId: "123456789012",
    IpPermissions: [
        {
            FromPort: 443,
            ToPort: 443,
            IpRanges: [{ CidrIp: "0.0.0.0/0" }]
        }
    ]
};

const mockNonCompliantSG = {
    GroupId: "sg-noncompliant",
    GroupName: "noncompliant-sg",
    OwnerId: "123456789012",
    IpPermissions: [
        {
            FromPort: 22,
            ToPort: 22,
            IpRanges: [{ CidrIp: "0.0.0.0/0" }]
        }
    ]
};

const mockMixedSG = {
    GroupId: "sg-mixed",
    GroupName: "mixed-sg",
    OwnerId: "123456789012",
    IpPermissions: [
        {
            FromPort: 22,
            ToPort: 22,
            IpRanges: [{ CidrIp: "10.0.0.0/8" }]
        },
        {
            FromPort: 3306,
            ToPort: 3306,
            Ipv6Ranges: [{ CidrIpv6: "::/0" }]
        }
    ]
};

describe("checkSecurityGroupHighRiskPorts", () => {
    beforeEach(() => {
        mockEC2Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for security groups with no high-risk ports exposed", async () => {
            mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
                SecurityGroups: [mockCompliantSG]
            });

            const result = await checkSecurityGroupHighRiskPorts.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("sg-compliant");
        });

        it("should return PASS for security groups with restricted high-risk ports", async () => {
            const restrictedSG = {
                ...mockNonCompliantSG,
                IpPermissions: [{
                    FromPort: 22,
                    ToPort: 22,
                    IpRanges: [{ CidrIp: "192.168.1.0/24" }]
                }]
            };

            mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
                SecurityGroups: [restrictedSG]
            });

            const result = await checkSecurityGroupHighRiskPorts.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for security groups with unrestricted high-risk ports", async () => {
            mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
                SecurityGroups: [mockNonCompliantSG]
            });

            const result = await checkSecurityGroupHighRiskPorts.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("22");
        });

        it("should return FAIL for security groups with unrestricted IPv6 high-risk ports", async () => {
            mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
                SecurityGroups: [mockMixedSG]
            });

            const result = await checkSecurityGroupHighRiskPorts.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("3306");
        });

        it("should handle multiple port ranges", async () => {
            const multiPortSG = {
                ...mockNonCompliantSG,
                IpPermissions: [{
                    FromPort: 20,
                    ToPort: 25,
                    IpRanges: [{ CidrIp: "0.0.0.0/0" }]
                }]
            };

            mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
                SecurityGroups: [multiPortSG]
            });

            const result = await checkSecurityGroupHighRiskPorts.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("20");
        });
    });

    describe("Edge Cases", () => {
        it("should return NOTAPPLICABLE when no security groups exist", async () => {
            mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
                SecurityGroups: []
            });

            const result = await checkSecurityGroupHighRiskPorts.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
        });

        it("should handle security groups without GroupId", async () => {
            const invalidSG = { ...mockCompliantSG, GroupId: undefined };
            mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
                SecurityGroups: [invalidSG]
            });

            const result = await checkSecurityGroupHighRiskPorts.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
        });

        it("should return ERROR when API call fails", async () => {
            mockEC2Client.on(DescribeSecurityGroupsCommand).rejects(
                new Error("API Error")
            );

            const result = await checkSecurityGroupHighRiskPorts.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("API Error");
        });
    });
});