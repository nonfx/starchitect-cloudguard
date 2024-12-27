// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkIamWildcardActions from "./aws_iam_no_wildcard_actions";

const mockIAMClient = mockClient(IAMClient);

const mockPolicyWithWildcard = {
	PolicyName: "WildcardPolicy",
	Arn: "arn:aws:iam::123456789012:policy/WildcardPolicy",
	DefaultVersionId: "v1"
};

const mockPolicyWithoutWildcard = {
	PolicyName: "RestrictedPolicy",
	Arn: "arn:aws:iam::123456789012:policy/RestrictedPolicy",
	DefaultVersionId: "v1"
};

const wildcardPolicyDocument = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: "s3:*",
			Resource: "*"
		}
	]
};

const restrictedPolicyDocument = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: ["s3:GetObject", "s3:PutObject"],
			Resource: "arn:aws:s3:::my-bucket/*"
		}
	]
};

describe("checkIamWildcardActions", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for policies without wildcard actions", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicyWithoutWildcard]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(JSON.stringify(restrictedPolicyDocument))
				}
			});

			const result = await checkIamWildcardActions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("RestrictedPolicy");
		});

		it("should return NOTAPPLICABLE when no policies exist", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: []
			});

			const result = await checkIamWildcardActions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No customer managed policies found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for policies with wildcard actions", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicyWithWildcard]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(JSON.stringify(wildcardPolicyDocument))
				}
			});

			const result = await checkIamWildcardActions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Policy contains wildcard actions for services");
		});

		it("should handle mixed policy configurations", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicyWithWildcard, mockPolicyWithoutWildcard]
			});

			mockIAMClient
				.on(GetPolicyVersionCommand)
				.resolves({
					PolicyVersion: {
						Document: encodeURIComponent(JSON.stringify(wildcardPolicyDocument))
					}
				})
				.on(GetPolicyVersionCommand, { PolicyArn: mockPolicyWithoutWildcard.Arn })
				.resolves({
					PolicyVersion: {
						Document: encodeURIComponent(JSON.stringify(restrictedPolicyDocument))
					}
				});

			const result = await checkIamWildcardActions.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should handle ListPolicies API errors", async () => {
			mockIAMClient.on(ListPoliciesCommand).rejects(new Error("API Error"));

			const result = await checkIamWildcardActions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error listing policies: API Error");
		});

		it("should handle GetPolicyVersion API errors", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicyWithWildcard]
			});

			mockIAMClient.on(GetPolicyVersionCommand).rejects(new Error("Version not found"));

			const result = await checkIamWildcardActions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error fetching policy version");
		});

		it("should handle invalid policy documents", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [mockPolicyWithWildcard]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: "invalid-json"
				}
			});

			const result = await checkIamWildcardActions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error parsing policy document");
		});
	});
});
