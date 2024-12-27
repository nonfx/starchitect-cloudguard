// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	IAMClient,
	ListUsersCommand,
	ListGroupsCommand,
	ListRolesCommand,
	ListAttachedUserPoliciesCommand,
	ListAttachedGroupPoliciesCommand,
	ListAttachedRolePoliciesCommand
} from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkCloudShellAccess from "./aws_iam_cloudshell_access";

const mockIAMClient = mockClient(IAMClient);

const CLOUDSHELL_FULL_ACCESS_ARN = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess";

describe("checkCloudShellAccess", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when no entities have CloudShell access", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [] })
				.on(ListGroupsCommand)
				.resolves({ Groups: [] })
				.on(ListRolesCommand)
				.resolves({ Roles: [] });

			const result = await checkCloudShellAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe(
				"No entities with AWSCloudShellFullAccess policy found"
			);
		});

		it("should return PASS when entities exist but none have CloudShell access", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({
					Users: [{ UserName: "test-user", Arn: "arn:aws:iam::123456789012:user/test-user" }]
				})
				.on(ListAttachedUserPoliciesCommand)
				.resolves({
					AttachedPolicies: [{ PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" }]
				})
				.on(ListGroupsCommand)
				.resolves({ Groups: [] })
				.on(ListRolesCommand)
				.resolves({ Roles: [] });

			const result = await checkCloudShellAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when user has CloudShell access", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({
					Users: [{ UserName: "test-user", Arn: "arn:aws:iam::123456789012:user/test-user" }]
				})
				.on(ListAttachedUserPoliciesCommand)
				.resolves({
					AttachedPolicies: [{ PolicyArn: CLOUDSHELL_FULL_ACCESS_ARN }]
				})
				.on(ListGroupsCommand)
				.resolves({ Groups: [] })
				.on(ListRolesCommand)
				.resolves({ Roles: [] });

			const result = await checkCloudShellAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain(
				"User has AWSCloudShellFullAccess policy attached"
			);
		});

		it("should return FAIL when group has CloudShell access", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [] })
				.on(ListGroupsCommand)
				.resolves({
					Groups: [{ GroupName: "test-group", Arn: "arn:aws:iam::123456789012:group/test-group" }]
				})
				.on(ListAttachedGroupPoliciesCommand)
				.resolves({
					AttachedPolicies: [{ PolicyArn: CLOUDSHELL_FULL_ACCESS_ARN }]
				})
				.on(ListRolesCommand)
				.resolves({ Roles: [] });

			const result = await checkCloudShellAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain(
				"Group has AWSCloudShellFullAccess policy attached"
			);
		});

		it("should return FAIL when role has CloudShell access", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [] })
				.on(ListGroupsCommand)
				.resolves({ Groups: [] })
				.on(ListRolesCommand)
				.resolves({
					Roles: [{ RoleName: "test-role", Arn: "arn:aws:iam::123456789012:role/test-role" }]
				})
				.on(ListAttachedRolePoliciesCommand)
				.resolves({
					AttachedPolicies: [{ PolicyArn: CLOUDSHELL_FULL_ACCESS_ARN }]
				});

			const result = await checkCloudShellAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain(
				"Role has AWSCloudShellFullAccess policy attached"
			);
		});

		it("should return multiple FAIL results when multiple entities have CloudShell access", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({
					Users: [{ UserName: "test-user", Arn: "arn:aws:iam::123456789012:user/test-user" }]
				})
				.on(ListAttachedUserPoliciesCommand)
				.resolves({
					AttachedPolicies: [{ PolicyArn: CLOUDSHELL_FULL_ACCESS_ARN }]
				})
				.on(ListGroupsCommand)
				.resolves({
					Groups: [{ GroupName: "test-group", Arn: "arn:aws:iam::123456789012:group/test-group" }]
				})
				.on(ListAttachedGroupPoliciesCommand)
				.resolves({
					AttachedPolicies: [{ PolicyArn: CLOUDSHELL_FULL_ACCESS_ARN }]
				})
				.on(ListRolesCommand)
				.resolves({ Roles: [] });

			const result = await checkCloudShellAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.FAIL)).toBe(true);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockIAMClient.on(ListUsersCommand).rejects(new Error("API Error"));

			const result = await checkCloudShellAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudShell access");
		});
	});
});
