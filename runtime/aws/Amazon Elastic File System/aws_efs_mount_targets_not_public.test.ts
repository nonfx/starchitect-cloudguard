import { EFSClient, DescribeMountTargetsCommand } from "@aws-sdk/client-efs";
import { EC2Client, DescribeSubnetsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkEfsMountTargetsPublicSubnets from "./aws_efs_mount_targets_not_public";

const mockEfsClient = mockClient(EFSClient);
const mockEc2Client = mockClient(EC2Client);

const mockMountTarget = {
    MountTargetId: "fsmt-12345678",
    SubnetId: "subnet-12345678",
    FileSystemId: "fs-12345678"
};

const mockPublicSubnet = {
    SubnetId: "subnet-12345678",
    MapPublicIpOnLaunch: true,
    VpcId: "vpc-12345678"
};

const mockPrivateSubnet = {
    SubnetId: "subnet-12345678",
    MapPublicIpOnLaunch: false,
    VpcId: "vpc-12345678"
};

describe("checkEfsMountTargetsPublicSubnets", () => {
    beforeEach(() => {
        mockEfsClient.reset();
        mockEc2Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when mount target is in private subnet", async () => {
            mockEfsClient.on(DescribeMountTargetsCommand).resolves({
                MountTargets: [mockMountTarget]
            });
            mockEc2Client.on(DescribeSubnetsCommand).resolves({
                Subnets: [mockPrivateSubnet]
            });

            const result = await checkEfsMountTargetsPublicSubnets("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe(mockMountTarget.MountTargetId);
        });

        it("should return NOTAPPLICABLE when no mount targets exist", async () => {
            mockEfsClient.on(DescribeMountTargetsCommand).resolves({
                MountTargets: []
            });

            const result = await checkEfsMountTargetsPublicSubnets("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No EFS mount targets found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when mount target is in public subnet", async () => {
            mockEfsClient.on(DescribeMountTargetsCommand).resolves({
                MountTargets: [mockMountTarget]
            });
            mockEc2Client.on(DescribeSubnetsCommand).resolves({
                Subnets: [mockPublicSubnet]
            });

            const result = await checkEfsMountTargetsPublicSubnets("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("Mount target is associated with public subnet");
        });

        it("should handle mount targets without subnet IDs", async () => {
            mockEfsClient.on(DescribeMountTargetsCommand).resolves({
                MountTargets: [{ MountTargetId: "fsmt-12345678" }]
            });

            const result = await checkEfsMountTargetsPublicSubnets("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Mount target found without subnet ID");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when EFS API call fails", async () => {
            mockEfsClient.on(DescribeMountTargetsCommand).rejects(
                new Error("Failed to describe mount targets")
            );

            const result = await checkEfsMountTargetsPublicSubnets("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking EFS mount targets");
        });

        it("should return ERROR when EC2 API call fails", async () => {
            mockEfsClient.on(DescribeMountTargetsCommand).resolves({
                MountTargets: [mockMountTarget]
            });
            mockEc2Client.on(DescribeSubnetsCommand).rejects(
                new Error("Failed to describe subnets")
            );

            const result = await checkEfsMountTargetsPublicSubnets("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking subnet");
        });

        it("should return ERROR when subnet is not found", async () => {
            mockEfsClient.on(DescribeMountTargetsCommand).resolves({
                MountTargets: [mockMountTarget]
            });
            mockEc2Client.on(DescribeSubnetsCommand).resolves({
                Subnets: []
            });

            const result = await checkEfsMountTargetsPublicSubnets("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Subnet");
            expect(result.checks[0].message).toContain("not found");
        });
    });

    describe("Multiple Resources", () => {
        it("should handle multiple mount targets with mixed compliance", async () => {
            mockEfsClient.on(DescribeMountTargetsCommand).resolves({
                MountTargets: [
                    { ...mockMountTarget, MountTargetId: "fsmt-1", SubnetId: "subnet-1" },
                    { ...mockMountTarget, MountTargetId: "fsmt-2", SubnetId: "subnet-2" }
                ]
            });
            
            mockEc2Client
                .on(DescribeSubnetsCommand, { SubnetIds: ["subnet-1"] })
                .resolves({ Subnets: [mockPrivateSubnet] })
                .on(DescribeSubnetsCommand, { SubnetIds: ["subnet-2"] })
                .resolves({ Subnets: [mockPublicSubnet] });

            const result = await checkEfsMountTargetsPublicSubnets("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });
});