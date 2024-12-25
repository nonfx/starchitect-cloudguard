import {
	IAMClient,
	ListUsersCommand,
	ListUserPoliciesCommand,
	ListAttachedUserPoliciesCommand,
	ListGroupsForUserCommand
} from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkIamUserPermissionsThroughGroups from "./aws_iam_users_permissions_through_group";

const mockIAMClient = mockClient(IAMClient);

const mockUser1 = {
	UserName: "test-user-1",
	Arn: "arn:aws:iam::123456789012:user/test-user-1",
	CreateDate: new Date()
};

const mockUser2 = {
	UserName: "test-user-2",
	Arn: "arn:aws:iam::123456789012:user/test-user-2",
	CreateDate: new Date()
};

describe("checkIamUserPermissionsThroughGroups", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when user has only group permissions", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [mockUser1] })
				.on(ListUserPoliciesCommand)
				.resolves({ PolicyNames: [] })
				.on(ListAttachedUserPoliciesCommand)
				.resolves({ AttachedPolicies: [] })
				.on(ListGroupsForUserCommand)
				.resolves({ Groups: [{ GroupName: "test-group" }] });

			const result = await checkIamUserPermissionsThroughGroups.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockUser1.UserName);
		});

		it("should return NOTAPPLICABLE when no users exist", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [] });

			const result = await checkIamUserPermissionsThroughGroups.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No IAM users found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when user has inline policies", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [mockUser1] })
				.on(ListUserPoliciesCommand)
				.resolves({ PolicyNames: ["inline-policy"] })
				.on(ListAttachedUserPoliciesCommand)
				.resolves({ AttachedPolicies: [] })
				.on(ListGroupsForUserCommand)
				.resolves({ Groups: [{ GroupName: "test-group" }] });

			const result = await checkIamUserPermissionsThroughGroups.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("has inline policies");
		});

		it("should return FAIL when user has directly attached policies", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [mockUser1] })
				.on(ListUserPoliciesCommand)
				.resolves({ PolicyNames: [] })
				.on(ListAttachedUserPoliciesCommand)
				.resolves({
					AttachedPolicies: [{ PolicyName: "attached-policy", PolicyArn: "arn:policy" }]
				})
				.on(ListGroupsForUserCommand)
				.resolves({ Groups: [{ GroupName: "test-group" }] });

			const result = await checkIamUserPermissionsThroughGroups.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("has directly attached policies");
		});

		it("should return FAIL when user has no group membership", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [mockUser1] })
				.on(ListUserPoliciesCommand)
				.resolves({ PolicyNames: [] })
				.on(ListAttachedUserPoliciesCommand)
				.resolves({ AttachedPolicies: [] })
				.on(ListGroupsForUserCommand)
				.resolves({ Groups: [] });

			const result = await checkIamUserPermissionsThroughGroups.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("not member of any groups");
		});

		it("should handle multiple users with different configurations", async () => {
			mockIAMClient.on(ListUsersCommand).resolves({ Users: [mockUser1, mockUser2] });

			// User 1 - Compliant
			mockIAMClient
				.on(ListUserPoliciesCommand, { UserName: mockUser1.UserName })
				.resolves({ PolicyNames: [] })
				.on(ListAttachedUserPoliciesCommand, { UserName: mockUser1.UserName })
				.resolves({ AttachedPolicies: [] })
				.on(ListGroupsForUserCommand, { UserName: mockUser1.UserName })
				.resolves({ Groups: [{ GroupName: "test-group" }] });

			// User 2 - Non-compliant
			mockIAMClient
				.on(ListUserPoliciesCommand, { UserName: mockUser2.UserName })
				.resolves({ PolicyNames: ["inline-policy"] })
				.on(ListAttachedUserPoliciesCommand, { UserName: mockUser2.UserName })
				.resolves({ AttachedPolicies: [] })
				.on(ListGroupsForUserCommand, { UserName: mockUser2.UserName })
				.resolves({ Groups: [] });

			const result = await checkIamUserPermissionsThroughGroups.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListUsers fails", async () => {
			mockIAMClient.on(ListUsersCommand).rejects(new Error("Failed to list users"));

			const result = await checkIamUserPermissionsThroughGroups.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list users");
		});

		it("should handle errors for individual user checks", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [mockUser1] })
				.on(ListUserPoliciesCommand)
				.rejects(new Error("Failed to list user policies"));

			const result = await checkIamUserPermissionsThroughGroups.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list user policies");
		});
	});
});
