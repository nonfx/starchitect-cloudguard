//@ts-nocheck
import { IAMClient, ListUsersCommand, GetAccessKeyLastUsedCommand, ListAccessKeysCommand, GetLoginProfileCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkUnusedCredentials from "./check-unused-credentials";

const mockIAMClient = mockClient(IAMClient);

const mockUsers = [
    {
        UserName: "active-user",
        Arn: "arn:aws:iam::123456789012:user/active-user",
        CreateDate: new Date()
    },
    {
        UserName: "inactive-user",
        Arn: "arn:aws:iam::123456789012:user/inactive-user",
        CreateDate: new Date()
    }
];

describe("checkUnusedCredentials", () => {
    beforeEach(() => {
        mockIAMClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for users with recently used credentials", async () => {
            const recentDate = new Date();
            mockIAMClient
                .on(ListUsersCommand).resolves({ Users: [mockUsers[0]] })
                .on(GetLoginProfileCommand).resolves({ 
                    LoginProfile: { CreateDate: recentDate }
                })
                .on(ListAccessKeysCommand).resolves({
                    AccessKeyMetadata: [{ AccessKeyId: "AKIA123456789" }]
                })
                .on(GetAccessKeyLastUsedCommand).resolves({
                    AccessKeyLastUsed: { LastUsedDate: recentDate }
                });

            const result = await checkUnusedCredentials();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("active-user");
        });

        it("should return NOTAPPLICABLE when no users exist", async () => {
            mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });

            const result = await checkUnusedCredentials();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No IAM users found");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for users with old credentials", async () => {
            const oldDate = new Date();
            oldDate.setDate(oldDate.getDate() - 60); // 60 days old

            mockIAMClient
                .on(ListUsersCommand).resolves({ Users: [mockUsers[1]] })
                .on(GetLoginProfileCommand).resolves({ 
                    LoginProfile: { CreateDate: oldDate }
                })
                .on(ListAccessKeysCommand).resolves({
                    AccessKeyMetadata: [{ AccessKeyId: "AKIA987654321" }]
                })
                .on(GetAccessKeyLastUsedCommand).resolves({
                    AccessKeyLastUsed: { LastUsedDate: oldDate }
                });

            const result = await checkUnusedCredentials();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("User has credentials unused for more than 45 days");
        });

        it("should handle mixed credential usage scenarios", async () => {
            const recentDate = new Date();
            const oldDate = new Date(recentDate);
            oldDate.setDate(oldDate.getDate() - 60);

            mockIAMClient
                .on(ListUsersCommand).resolves({ Users: mockUsers })
                .on(GetLoginProfileCommand)
                .resolvesOnce({ LoginProfile: { CreateDate: recentDate } })
                .resolvesOnce({ LoginProfile: { CreateDate: oldDate } })
                .on(ListAccessKeysCommand).resolves({
                    AccessKeyMetadata: [{ AccessKeyId: "AKIA123456789" }]
                })
                .on(GetAccessKeyLastUsedCommand)
                .resolvesOnce({ AccessKeyLastUsed: { LastUsedDate: recentDate } })
                .resolvesOnce({ AccessKeyLastUsed: { LastUsedDate: oldDate } });

            const result = await checkUnusedCredentials();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when ListUsers fails", async () => {
            mockIAMClient.on(ListUsersCommand).rejects(new Error("API Error"));

            const result = await checkUnusedCredentials();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking IAM users");
        });

        it("should handle NoSuchEntity error for GetLoginProfile gracefully", async () => {
            mockIAMClient
                .on(ListUsersCommand).resolves({ Users: [mockUsers[0]] })
                .on(GetLoginProfileCommand).rejects({ name: 'NoSuchEntity' })
                .on(ListAccessKeysCommand).resolves({ AccessKeyMetadata: [] });

            const result = await checkUnusedCredentials();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
        });

        it("should return ERROR for specific users when credential check fails", async () => {
            mockIAMClient
                .on(ListUsersCommand).resolves({ Users: [mockUsers[0]] })
                .on(GetLoginProfileCommand).rejects(new Error("Access Denied"));

            const result = await checkUnusedCredentials();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking user credentials");
        });
    });
});