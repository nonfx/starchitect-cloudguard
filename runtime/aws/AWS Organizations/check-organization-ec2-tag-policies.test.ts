// @ts-nocheck
import { OrganizationsClient, ListPoliciesCommand } from "@aws-sdk/client-organizations";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkOrganizationTagPolicies from "./check-organization-ec2-tag-policies";

const mockOrganizationsClient = mockClient(OrganizationsClient);

const mockTagPolicies = [
	{
		Name: "test-policy-1",
		Arn: "arn:aws:organizations::123456789012:policy/o-abcd123456/tag_policy/p-12345678",
		Description: "Test Tag Policy 1"
	},
	{
		Name: "test-policy-2",
		Arn: "arn:aws:organizations::123456789012:policy/o-abcd123456/tag_policy/p-87654321",
		Description: "Test Tag Policy 2"
	}
];

describe("checkOrganizationTagPolicies", () => {
	beforeEach(() => {
		mockOrganizationsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when tag policies exist", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).resolves({
				Policies: mockTagPolicies
			});

			const result = await checkOrganizationTagPolicies.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-policy-1");
			expect(result.checks[0].resourceArn).toBe(mockTagPolicies[0].Arn);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].resourceName).toBe("test-policy-2");
			expect(result.checks[1].resourceArn).toBe(mockTagPolicies[1].Arn);
		});

		it("should handle single tag policy", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).resolves({
				Policies: [mockTagPolicies[0]]
			});

			const result = await checkOrganizationTagPolicies.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-policy-1");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no tag policies exist", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).resolves({
				Policies: []
			});

			const result = await checkOrganizationTagPolicies.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No TAG_POLICY found in the organization. Ensure at least one tag policy is enabled."
			);
		});

		it("should return FAIL when Policies field is undefined", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).resolves({});

			const result = await checkOrganizationTagPolicies.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when Organizations is not in use", async () => {
			const error = new Error("Organizations not in use");
			error.name = "AWSOrganizationsNotInUseException";
			mockOrganizationsClient.on(ListPoliciesCommand).rejects(error);

			const result = await checkOrganizationTagPolicies.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("AWS Organizations is not enabled for this account");
		});

		it("should return ERROR on API failure", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).rejects(new Error("API Error"));

			const result = await checkOrganizationTagPolicies.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking organization tag policies: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockOrganizationsClient.on(ListPoliciesCommand).rejects("Unknown error");

			const result = await checkOrganizationTagPolicies.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe(
				"Error checking organization tag policies: Unknown error"
			);
		});
	});
});
