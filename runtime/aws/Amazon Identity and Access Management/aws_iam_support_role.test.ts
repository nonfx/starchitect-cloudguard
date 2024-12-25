import { IAMClient, ListRolesCommand, ListAttachedRolePoliciesCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkIamSupportRole from "./aws_iam_support_role";

const mockIAMClient = mockClient(IAMClient);

const mockRole1 = {
	RoleName: "test-support-role",
	Arn: "arn:aws:iam::123456789012:role/test-support-role"
};

const mockRole2 = {
	RoleName: "test-other-role",
	Arn: "arn:aws:iam::123456789012:role/test-other-role"
};

describe("checkIamSupportRole", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when a role has AWSSupportAccess policy attached", async () => {
			mockIAMClient.on(ListRolesCommand).resolves({
				Roles: [mockRole1]
			});
			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: [
					{
						PolicyName: "AWSSupportAccess",
						PolicyArn: "arn:aws:iam::aws:policy/AWSSupportAccess"
					}
				]
			});

			const result = await checkIamSupportRole.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-support-role");
		});

		it("should handle multiple roles with support access", async () => {
			mockIAMClient.on(ListRolesCommand).resolves({
				Roles: [mockRole1, mockRole2]
			});
			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: [
					{
						PolicyName: "AWSSupportAccess",
						PolicyArn: "arn:aws:iam::aws:policy/AWSSupportAccess"
					}
				]
			});

			const result = await checkIamSupportRole.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no role has AWSSupportAccess policy", async () => {
			mockIAMClient.on(ListRolesCommand).resolves({
				Roles: [mockRole1]
			});
			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: [
					{
						PolicyName: "OtherPolicy",
						PolicyArn: "arn:aws:iam::aws:policy/OtherPolicy"
					}
				]
			});

			const result = await checkIamSupportRole.execute();
			expect(result.checks).toHaveLength(2); // One for the role and one overall check
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].message).toBe(
				"No IAM role found with AWSSupportAccess policy attached"
			);
		});

		it("should handle roles without name or ARN", async () => {
			mockIAMClient.on(ListRolesCommand).resolves({
				Roles: [{}] // Invalid role without name or ARN
			});

			const result = await checkIamSupportRole.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Role found without name or ARN");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no roles exist", async () => {
			mockIAMClient.on(ListRolesCommand).resolves({
				Roles: []
			});

			const result = await checkIamSupportRole.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No IAM roles found");
		});

		it("should handle pagination", async () => {
			mockIAMClient
				.on(ListRolesCommand)
				.resolvesOnce({
					Roles: [mockRole1],
					Marker: "token1"
				})
				.resolvesOnce({
					Roles: [mockRole2]
				});
			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: [
					{
						PolicyName: "AWSSupportAccess",
						PolicyArn: "arn:aws:iam::aws:policy/AWSSupportAccess"
					}
				]
			});

			const result = await checkIamSupportRole.execute();
			expect(result.checks).toHaveLength(2);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListRoles fails", async () => {
			mockIAMClient.on(ListRolesCommand).rejects(new Error("API Error"));

			const result = await checkIamSupportRole.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking IAM roles");
		});

		it("should return ERROR when ListAttachedRolePolicies fails", async () => {
			mockIAMClient.on(ListRolesCommand).resolves({
				Roles: [mockRole1]
			});
			mockIAMClient.on(ListAttachedRolePoliciesCommand).rejects(new Error("Access Denied"));

			const result = await checkIamSupportRole.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking role policies");
		});
	});
});
