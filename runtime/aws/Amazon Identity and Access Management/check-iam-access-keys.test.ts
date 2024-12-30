// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import { IAMClient, ListAccessKeysCommand, ListUsersCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkIamUserAccessKeys from "./check-iam-access-keys";

const mockIAMClient = mockClient(IAMClient);

const mockUsers = [
	{
		UserName: "user1",
		Arn: "arn:aws:iam::123456789012:user/user1",
		CreateDate: new Date()
	},
	{
		UserName: "user2",
		Arn: "arn:aws:iam::123456789012:user/user2",
		CreateDate: new Date()
	}
];

describe("checkIamUserAccessKeys", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when users have single active access key", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: mockUsers });
			mockIAMClient.on(ListAccessKeysCommand).resolves({
				AccessKeyMetadata: [{ Status: "Active", AccessKeyId: "AKIA123456789" }]
			});

			const result = await checkIamUserAccessKeys.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return PASS when user has one active and one inactive key", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(ListAccessKeysCommand).resolves({
				AccessKeyMetadata: [
					{ Status: "Active", AccessKeyId: "AKIA123456789" },
					{ Status: "Inactive", AccessKeyId: "AKIA987654321" }
				]
			});

			const result = await checkIamUserAccessKeys.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no users exist", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });

			const result = await checkIamUserAccessKeys.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No IAM users found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when user has multiple active access keys", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUsers[0]] });
			mockIAMClient.on(ListAccessKeysCommand).resolves({
				AccessKeyMetadata: [
					{ Status: "Active", AccessKeyId: "AKIA123456789" },
					{ Status: "Active", AccessKeyId: "AKIA987654321" }
				]
			});

			const result = await checkIamUserAccessKeys.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("2 active access keys");
		});

		it("should handle mixed compliance results", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: mockUsers });
			mockIAMClient
				.on(ListAccessKeysCommand, { UserName: "user1" })
				.resolves({
					AccessKeyMetadata: [{ Status: "Active", AccessKeyId: "AKIA123456789" }]
				})
				.on(ListAccessKeysCommand, { UserName: "user2" })
				.resolves({
					AccessKeyMetadata: [
						{ Status: "Active", AccessKeyId: "AKIA123456789" },
						{ Status: "Active", AccessKeyId: "AKIA987654321" }
					]
				});

			const result = await checkIamUserAccessKeys.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListUsers fails", async () => {
			mockIAMClient.on(ListUsersCommand).rejects(new Error("API Error"));

			const result = await checkIamUserAccessKeys.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking IAM users");
		});

		it("should handle errors for specific users", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: mockUsers });
			mockIAMClient.on(ListAccessKeysCommand).rejects(new Error("Access Denied"));

			const result = await checkIamUserAccessKeys.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking access keys");
		});

		it("should handle users without UserName", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({
				Users: [{ Arn: "arn:aws:iam::123456789012:user/unnamed" }]
			});

			const result = await checkIamUserAccessKeys.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("User found without username");
		});
	});
});
