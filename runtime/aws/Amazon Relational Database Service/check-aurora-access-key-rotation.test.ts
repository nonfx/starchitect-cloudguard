// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import { IAMClient, ListUsersCommand, ListAccessKeysCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAccessKeyRotation from "./check-aurora-access-key-rotation";

const mockIAMClient = mockClient(IAMClient);

const createDate = new Date();
const oldDate = new Date();
oldDate.setDate(oldDate.getDate() - 100); // 100 days old

const mockUsers = [
	{
		UserName: "test-user-1",
		Arn: "arn:aws:iam::123456789012:user/test-user-1",
		CreateDate: createDate
	},
	{
		UserName: "test-user-2",
		Arn: "arn:aws:iam::123456789012:user/test-user-2",
		CreateDate: createDate
	}
];

describe("checkAccessKeyRotation", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for users with no access keys", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(ListAccessKeysCommand).resolves({ AccessKeyMetadata: [] });

			const result = await checkAccessKeyRotation.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("User has no access keys");
		});

		it("should return PASS for users with recent access keys", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(ListAccessKeysCommand).resolves({
				AccessKeyMetadata: [
					{
						AccessKeyId: "AKIA123456789",
						CreateDate: createDate,
						UserName: "test-user-1"
					}
				]
			});

			const result = await checkAccessKeyRotation.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no users exist", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });

			const result = await checkAccessKeyRotation.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No IAM users found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for users with old access keys", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(ListAccessKeysCommand).resolves({
				AccessKeyMetadata: [
					{
						AccessKeyId: "AKIA123456789",
						CreateDate: oldDate,
						UserName: "test-user-1"
					}
				]
			});

			const result = await checkAccessKeyRotation.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("days old");
		});

		it("should handle multiple access keys with mixed compliance", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(ListAccessKeysCommand).resolves({
				AccessKeyMetadata: [
					{
						AccessKeyId: "AKIA123456789",
						CreateDate: createDate,
						UserName: "test-user-1"
					},
					{
						AccessKeyId: "AKIA987654321",
						CreateDate: oldDate,
						UserName: "test-user-1"
					}
				]
			});

			const result = await checkAccessKeyRotation.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListUsers fails", async () => {
			mockIAMClient.on(ListUsersCommand).rejects(new Error("Failed to list users"));

			const result = await checkAccessKeyRotation.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list users");
		});

		it("should return ERROR for specific users when ListAccessKeys fails", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(ListAccessKeysCommand).rejects(new Error("Access denied"));

			const result = await checkAccessKeyRotation.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking access keys");
		});

		it("should handle missing CreateDate in access keys", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(ListAccessKeysCommand).resolves({
				AccessKeyMetadata: [
					{
						AccessKeyId: "AKIA123456789",
						UserName: "test-user-1"
						// CreateDate intentionally omitted
					}
				]
			});

			const result = await checkAccessKeyRotation.execute();
			expect(result.checks).toHaveLength(0);
		});
	});
});
