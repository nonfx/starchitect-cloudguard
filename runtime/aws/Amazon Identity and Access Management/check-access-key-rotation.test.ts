// @ts-nocheck
import { IAMClient, ListAccessKeysCommand, GetAccessKeyLastUsedCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAccessKeyRotation from "./check-access-key-rotation";

const mockIAMClient = mockClient(IAMClient);

const createDate = (daysAgo: number) => {
    const date = new Date();
    date.setDate(date.getDate() - daysAgo);
    return date;
};

describe("checkAccessKeyRotation", () => {
    beforeEach(() => {
        mockIAMClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for access keys less than 90 days old", async () => {
            mockIAMClient.on(ListAccessKeysCommand).resolves({
                AccessKeyMetadata: [{
                    AccessKeyId: "AKIA123456789",
                    CreateDate: createDate(30)
                }]
            });

            mockIAMClient.on(GetAccessKeyLastUsedCommand).resolves({
                UserName: "testuser"
            });

            const result = await checkAccessKeyRotation();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("AKIA123456789");
        });

        it("should return NOTAPPLICABLE when no access keys exist", async () => {
            mockIAMClient.on(ListAccessKeysCommand).resolves({
                AccessKeyMetadata: []
            });

            const result = await checkAccessKeyRotation();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No access keys found");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for access keys older than 90 days", async () => {
            mockIAMClient.on(ListAccessKeysCommand).resolves({
                AccessKeyMetadata: [{
                    AccessKeyId: "AKIA123456789",
                    CreateDate: createDate(100)
                }]
            });

            mockIAMClient.on(GetAccessKeyLastUsedCommand).resolves({
                UserName: "testuser"
            });

            const result = await checkAccessKeyRotation();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("100 days old");
        });

        it("should handle multiple access keys with mixed compliance", async () => {
            mockIAMClient.on(ListAccessKeysCommand).resolves({
                AccessKeyMetadata: [
                    {
                        AccessKeyId: "AKIA123456789",
                        CreateDate: createDate(30)
                    },
                    {
                        AccessKeyId: "AKIA987654321",
                        CreateDate: createDate(120)
                    }
                ]
            });

            mockIAMClient.on(GetAccessKeyLastUsedCommand).resolves({
                UserName: "testuser"
            });

            const result = await checkAccessKeyRotation();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when ListAccessKeys fails", async () => {
            mockIAMClient.on(ListAccessKeysCommand).rejects(
                new Error("Failed to list access keys")
            );

            const result = await checkAccessKeyRotation();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Failed to list access keys");
        });

        it("should return ERROR for keys with missing metadata", async () => {
            mockIAMClient.on(ListAccessKeysCommand).resolves({
                AccessKeyMetadata: [{
                    AccessKeyId: "AKIA123456789"
                    // Missing CreateDate
                }]
            });

            const result = await checkAccessKeyRotation();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Access key missing required metadata");
        });

        it("should handle GetAccessKeyLastUsed failures", async () => {
            mockIAMClient.on(ListAccessKeysCommand).resolves({
                AccessKeyMetadata: [{
                    AccessKeyId: "AKIA123456789",
                    CreateDate: createDate(30)
                }]
            });

            mockIAMClient.on(GetAccessKeyLastUsedCommand).rejects(
                new Error("Failed to get last used info")
            );

            const result = await checkAccessKeyRotation();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Failed to get last used info");
        });
    });
});