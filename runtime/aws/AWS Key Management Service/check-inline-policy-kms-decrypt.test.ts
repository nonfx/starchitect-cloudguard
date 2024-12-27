// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	IAMClient,
	ListUsersCommand,
	ListRolesCommand,
	ListGroupsCommand,
	ListUserPoliciesCommand,
	ListRolePoliciesCommand,
	ListGroupPoliciesCommand,
	GetUserPolicyCommand,
	GetRolePolicyCommand,
	GetGroupPolicyCommand
} from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkInlinePolicyKmsDecrypt from "./check-inline-policy-kms-decrypt";

const mockIAMClient = mockClient(IAMClient);

const violatingPolicyDocument = encodeURIComponent(
	JSON.stringify({
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Action: ["kms:Decrypt"],
				Resource: "*"
			}
		]
	})
);

const compliantPolicyDocument = encodeURIComponent(
	JSON.stringify({
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Action: ["kms:Decrypt"],
				Resource: "arn:aws:kms:us-east-1:123456789012:key/specific-key-id"
			}
		]
	})
);

describe("checkInlinePolicyKmsDecrypt", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for policies with specific KMS key resources", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({
					Users: [{ UserName: "test-user", Arn: "arn:aws:iam::123456789012:user/test-user" }]
				})
				.on(ListUserPoliciesCommand)
				.resolves({ PolicyNames: ["test-policy"] })
				.on(GetUserPolicyCommand)
				.resolves({ PolicyDocument: compliantPolicyDocument });

			const result = await checkInlinePolicyKmsDecrypt.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("User:test-user/Policy:test-policy");
		});

		it("should return NOTAPPLICABLE when no IAM principals exist", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [] })
				.on(ListRolesCommand)
				.resolves({ Roles: [] })
				.on(ListGroupsCommand)
				.resolves({ Groups: [] });

			const result = await checkInlinePolicyKmsDecrypt.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for user policies allowing decrypt on all keys", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({
					Users: [{ UserName: "test-user", Arn: "arn:aws:iam::123456789012:user/test-user" }]
				})
				.on(ListUserPoliciesCommand)
				.resolves({ PolicyNames: ["test-policy"] })
				.on(GetUserPolicyCommand)
				.resolves({ PolicyDocument: violatingPolicyDocument });

			const result = await checkInlinePolicyKmsDecrypt.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Inline policy allows KMS decrypt actions on all keys");
		});

		it("should return FAIL for role policies allowing decrypt on all keys", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [] })
				.on(ListRolesCommand)
				.resolves({
					Roles: [{ RoleName: "test-role", Arn: "arn:aws:iam::123456789012:role/test-role" }]
				})
				.on(ListRolePoliciesCommand)
				.resolves({ PolicyNames: ["test-policy"] })
				.on(GetRolePolicyCommand)
				.resolves({ PolicyDocument: violatingPolicyDocument });

			const result = await checkInlinePolicyKmsDecrypt.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});

		it("should return FAIL for group policies allowing decrypt on all keys", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({ Users: [] })
				.on(ListRolesCommand)
				.resolves({ Roles: [] })
				.on(ListGroupsCommand)
				.resolves({
					Groups: [{ GroupName: "test-group", Arn: "arn:aws:iam::123456789012:group/test-group" }]
				})
				.on(ListGroupPoliciesCommand)
				.resolves({ PolicyNames: ["test-policy"] })
				.on(GetGroupPolicyCommand)
				.resolves({ PolicyDocument: violatingPolicyDocument });

			const result = await checkInlinePolicyKmsDecrypt.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when listing IAM principals fails", async () => {
			mockIAMClient.on(ListUsersCommand).rejects(new Error("API Error"));

			const result = await checkInlinePolicyKmsDecrypt.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking IAM policies");
		});

		it("should return ERROR when getting policy content fails", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({
					Users: [{ UserName: "test-user", Arn: "arn:aws:iam::123456789012:user/test-user" }]
				})
				.on(ListUserPoliciesCommand)
				.resolves({ PolicyNames: ["test-policy"] })
				.on(GetUserPolicyCommand)
				.rejects(new Error("Access Denied"));

			const result = await checkInlinePolicyKmsDecrypt.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking policy");
		});
	});

	describe("Mixed Scenarios", () => {
		it("should handle multiple principals with different policy configurations", async () => {
			mockIAMClient
				.on(ListUsersCommand)
				.resolves({
					Users: [
						{ UserName: "compliant-user", Arn: "arn:aws:iam::123456789012:user/compliant-user" },
						{ UserName: "violating-user", Arn: "arn:aws:iam::123456789012:user/violating-user" }
					]
				})
				.on(ListUserPoliciesCommand)
				.resolves({ PolicyNames: ["test-policy"] })
				.on(GetUserPolicyCommand, { UserName: "compliant-user" })
				.resolves({ PolicyDocument: compliantPolicyDocument })
				.on(GetUserPolicyCommand, { UserName: "violating-user" })
				.resolves({ PolicyDocument: violatingPolicyDocument });

			const result = await checkInlinePolicyKmsDecrypt.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
