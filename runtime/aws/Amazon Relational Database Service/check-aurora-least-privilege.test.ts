//@ts-nocheck
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { 
    IAMClient, 
    GetRolePolicyCommand, 
    ListRolePoliciesCommand, 
    ListAttachedRolePoliciesCommand, 
    GetPolicyVersionCommand 
} from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAuroraLeastPrivilegeCompliance from "./check-aurora-least-privilege";

const mockRDSClient = mockClient(RDSClient);
const mockIAMClient = mockClient(IAMClient);

const mockAuroraInstance = {
    DBInstanceIdentifier: "test-aurora-1",
    DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-aurora-1",
    Engine: "aurora-mysql",
    AssociatedRoles: [{
        RoleArn: "arn:aws:iam::123456789012:role/aurora-role"
    }]
};

describe("checkAuroraLeastPrivilegeCompliance", () => {
    beforeEach(() => {
        mockRDSClient.reset();
        mockIAMClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when roles follow least privilege principle", async () => {
            mockRDSClient.on(DescribeDBInstancesCommand).resolves({
                DBInstances: [mockAuroraInstance]
            });

            mockIAMClient.on(ListRolePoliciesCommand).resolves({
                PolicyNames: ["inline-policy"]
            });

            mockIAMClient.on(GetRolePolicyCommand).resolves({
                PolicyDocument: JSON.stringify({
                    Version: "2012-10-17",
                    Statement: [{
                        Effect: "Allow",
                        Action: ["rds:DescribeDBInstances"],
                        Resource: "arn:aws:rds:*:*:db:test-aurora-*"
                    }]
                })
            });

            mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
                AttachedPolicies: []
            });

            const result = await checkAuroraLeastPrivilegeCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("test-aurora-1");
        });

        it("should return NOTAPPLICABLE when no Aurora instances exist", async () => {
            mockRDSClient.on(DescribeDBInstancesCommand).resolves({
                DBInstances: []
            });

            const result = await checkAuroraLeastPrivilegeCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when inline policy has excessive privileges", async () => {
            mockRDSClient.on(DescribeDBInstancesCommand).resolves({
                DBInstances: [mockAuroraInstance]
            });

            mockIAMClient.on(ListRolePoliciesCommand).resolves({
                PolicyNames: ["over-privileged-policy"]
            });

            mockIAMClient.on(GetRolePolicyCommand).resolves({
                PolicyDocument: JSON.stringify({
                    Version: "2012-10-17",
                    Statement: [{
                        Effect: "Allow",
                        Action: "*",
                        Resource: "*"
                    }]
                })
            });

            mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
                AttachedPolicies: []
            });

            const result = await checkAuroraLeastPrivilegeCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("excessive privileges");
        });

        it("should return FAIL when attached policy has excessive privileges", async () => {
            mockRDSClient.on(DescribeDBInstancesCommand).resolves({
                DBInstances: [mockAuroraInstance]
            });

            mockIAMClient.on(ListRolePoliciesCommand).resolves({
                PolicyNames: []
            });

            mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
                AttachedPolicies: [{
                    PolicyName: "over-privileged-policy",
                    PolicyArn: "arn:aws:iam::aws:policy/over-privileged"
                }]
            });

            mockIAMClient.on(GetPolicyVersionCommand).resolves({
                PolicyVersion: {
                    Document: {
                        Version: "2012-10-17",
                        Statement: [{
                            Effect: "Allow",
                            Action: "rds:*",
                            Resource: "*"
                        }]
                    }
                }
            });

            const result = await checkAuroraLeastPrivilegeCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when RDS API call fails", async () => {
            mockRDSClient.on(DescribeDBInstancesCommand).rejects(
                new Error("RDS API Error")
            );

            const result = await checkAuroraLeastPrivilegeCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("RDS API Error");
        });

        it("should return ERROR when IAM API call fails", async () => {
            mockRDSClient.on(DescribeDBInstancesCommand).resolves({
                DBInstances: [mockAuroraInstance]
            });

            mockIAMClient.on(ListRolePoliciesCommand).rejects(
                new Error("IAM API Error")
            );

            const result = await checkAuroraLeastPrivilegeCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("IAM API Error");
        });
    });
});