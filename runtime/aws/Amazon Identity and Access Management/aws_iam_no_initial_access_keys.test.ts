import { IAMClient, ListUsersCommand, GetLoginProfileCommand, ListAccessKeysCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkInitialAccessKeys from "./aws_iam_no_initial_access_keys";

const mockIAMClient = mockClient(IAMClient);

const mockUsers = [
    {
        UserName: "user-1",
        Arn: "arn:aws:iam::123456789012:user/user-1",
        CreateDate: new Date()
    },
    {
        UserName: "user-2",
        Arn: "arn:aws:iam::123456789012:user/user-2",
        CreateDate: new Date()
    }
];

describe("checkInitialAccessKeys", () => {
    beforeEach(() => {
        mockIAMClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for users without console access", async () => {
            mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
            mockIAMClient.on(GetLoginProfileCommand).rejects({ name: "NoSuchEntity" });

            const result = await checkInitialAccessKeys.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].message).toBe("User does not have console access");
        });

        it("should return PASS for users with console access but no access keys", async () => {
            mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
            mockIAMClient.on(GetLoginProfileCommand).resolves({});
            mockIAMClient.on(ListAccessKeysCommand).resolves({ AccessKeyMetadata: [] });

            const result = await checkInitialAccessKeys.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
        });

        it("should return NOTAPPLICABLE when no IAM users exist", async () => {
            mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });

            const result = await checkInitialAccessKeys.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No IAM users found");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for users with both console access and access keys", async () => {
            mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
            mockIAMClient.on(GetLoginProfileCommand).resolves({});
            mockIAMClient.on(ListAccessKeysCommand).resolves({
                AccessKeyMetadata: [{ AccessKeyId: "AKIA123456789" }]
            });

            const result = await checkInitialAccessKeys.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("User has both console access and access keys");
        });

        it("should handle multiple users with mixed compliance", async () => {
            mockIAMClient.on(ListUsersCommand).resolves({ Users: mockUsers });
            mockIAMClient
                .on(GetLoginProfileCommand, { UserName: "user-1" }).resolves({})
                .on(GetLoginProfileCommand, { UserName: "user-2" }).resolves({});
            mockIAMClient
                .on(ListAccessKeysCommand, { UserName: "user-1" }).resolves({ AccessKeyMetadata: [{ AccessKeyId: "AKIA123" }] })
                .on(ListAccessKeysCommand, { UserName: "user-2" }).resolves({ AccessKeyMetadata: [] });

            const result = await checkInitialAccessKeys.execute();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when ListUsers fails", async () => {
            mockIAMClient.on(ListUsersCommand).rejects(new Error("Failed to list users"));

            const result = await checkInitialAccessKeys.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error listing IAM users");
        });

        it("should return ERROR for specific user when GetLoginProfile fails unexpectedly", async () => {
            mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
            mockIAMClient.on(GetLoginProfileCommand).rejects(new Error("Internal error"));

            const result = await checkInitialAccessKeys.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking user");
        });

        it("should return ERROR when ListAccessKeys fails", async () => {
            mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
            mockIAMClient.on(GetLoginProfileCommand).resolves({});
            mockIAMClient.on(ListAccessKeysCommand).rejects(new Error("Access denied"));

            const result = await checkInitialAccessKeys.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking user");
        });
    });
});