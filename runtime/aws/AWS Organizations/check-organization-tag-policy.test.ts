// @ts-nocheck
import {
	OrganizationsClient,
	ListPoliciesCommand,
	DescribePolicyCommand
} from "@aws-sdk/client-organizations";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkTagPolicyCompliance from "./check-organization-tag-policy";

const mockOrganizationsClient = mockClient(OrganizationsClient);

const validTagPolicy = {
	tags: {
		environment: {
			tag_key: { assign: true },
			tag_value: { assign: true },
			operators_allowed_for_child_policies: ["ENFORCED_FOR"],
			enforced_for: {
				assign: ["ec2:image", "ec2:instance", "ec2:reserved-instances"]
			}
		}
	}
};

const invalidTagPolicy = {
	tags: {
		environment: {
			tag_key: { assign: true },
			tag_value: { assign: true },
			operators_allowed_for_child_policies: ["ENFORCED_FOR"],
			enforced_for: {
				assign: ["ec2:instance"] // Missing required resource types
			}
		}
	}
};

describe("checkTagPolicy", () => {
	beforeEach(() => {
		mockOrganizationsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when valid tag policy exists", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicySummary: {
							Id: "p-123456",
							Name: "ValidPolicy",
							Arn: "arn:aws:organizations::123456789012:policy/o-abcd123456/tag_policy/p-123456"
						}
					}
				]
			});

			mockOrganizationsClient.on(DescribePolicyCommand).resolves({
				Policy: {
					Content: JSON.stringify(validTagPolicy)
				}
			});

			const result = await checkTagPolicyCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("ValidPolicy");
		});

		it("should handle multiple policies with at least one valid policy", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicySummary: {
							Id: "p-123456",
							Name: "ValidPolicy",
							Arn: "arn:aws:organizations::123456789012:policy/o-abcd123456/tag_policy/p-123456"
						}
					},
					{
						PolicySummary: {
							Id: "p-789012",
							Name: "InvalidPolicy",
							Arn: "arn:aws:organizations::123456789012:policy/o-abcd123456/tag_policy/p-789012"
						}
					}
				]
			});

			mockOrganizationsClient.on(DescribePolicyCommand).resolves({
				Policy: {
					Content: JSON.stringify(validTagPolicy)
				}
			});

			const result = await checkTagPolicyCompliance.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.some(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no tag policies exist", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).resolves({ Policies: [] });

			const result = await checkTagPolicyCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No tag policies found in the organization");
		});

		it("should return FAIL for invalid tag policy", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicySummary: {
							Id: "p-123456",
							Name: "InvalidPolicy",
							Arn: "arn:aws:organizations::123456789012:policy/o-abcd123456/tag_policy/p-123456"
						}
					}
				]
			});

			mockOrganizationsClient.on(DescribePolicyCommand).resolves({
				Policy: {
					Content: JSON.stringify(invalidTagPolicy)
				}
			});

			const result = await checkTagPolicyCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Tag policy does not enforce required EC2 resource types"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListPolicies fails", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).rejects(new Error("Access denied"));

			const result = await checkTagPolicyCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking tag policies: Access denied");
		});

		it("should return ERROR when DescribePolicy fails", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicySummary: {
							Id: "p-123456",
							Name: "TestPolicy",
							Arn: "arn:aws:organizations::123456789012:policy/o-abcd123456/tag_policy/p-123456"
						}
					}
				]
			});

			mockOrganizationsClient.on(DescribePolicyCommand).rejects(new Error("Policy not found"));

			const result = await checkTagPolicyCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking policy: Policy not found");
		});

		it("should handle invalid JSON in policy content", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicySummary: {
							Id: "p-123456",
							Name: "InvalidJSON",
							Arn: "arn:aws:organizations::123456789012:policy/o-abcd123456/tag_policy/p-123456"
						}
					}
				]
			});

			mockOrganizationsClient.on(DescribePolicyCommand).resolves({
				Policy: {
					Content: "invalid-json"
				}
			});

			const result = await checkTagPolicyCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking policy");
		});
	});
});
