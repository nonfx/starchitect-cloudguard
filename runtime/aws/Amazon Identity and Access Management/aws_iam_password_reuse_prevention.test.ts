import { IAMClient, GetAccountPasswordPolicyCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkPasswordReusePreventionCompliance from "./aws_iam_password_reuse_prevention";

const mockIAMClient = mockClient(IAMClient);

describe("checkPasswordReusePreventionCompliance", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when password reuse prevention meets requirement", async () => {
			mockIAMClient.on(GetAccountPasswordPolicyCommand).resolves({
				PasswordPolicy: {
					PasswordReusePrevention: 24
				}
			});

			const result = await checkPasswordReusePreventionCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("Password Policy");
			expect(result.checks[0].message).toBeUndefined();
		});

		it("should return PASS when password reuse prevention exceeds requirement", async () => {
			mockIAMClient.on(GetAccountPasswordPolicyCommand).resolves({
				PasswordPolicy: {
					PasswordReusePrevention: 30
				}
			});

			const result = await checkPasswordReusePreventionCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when password reuse prevention is below requirement", async () => {
			mockIAMClient.on(GetAccountPasswordPolicyCommand).resolves({
				PasswordPolicy: {
					PasswordReusePrevention: 12
				}
			});

			const result = await checkPasswordReusePreventionCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("should be at least 24");
		});

		it("should return FAIL when password reuse prevention is not set", async () => {
			mockIAMClient.on(GetAccountPasswordPolicyCommand).resolves({
				PasswordPolicy: {}
			});

			const result = await checkPasswordReusePreventionCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});

		it("should return FAIL when no password policy exists", async () => {
			mockIAMClient.on(GetAccountPasswordPolicyCommand).resolves({});

			const result = await checkPasswordReusePreventionCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No password policy is configured");
		});

		it("should return FAIL when NoSuchEntityException is thrown", async () => {
			mockIAMClient.on(GetAccountPasswordPolicyCommand).rejects({
				name: "NoSuchEntityException"
			});

			const result = await checkPasswordReusePreventionCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No password policy is configured");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockIAMClient.on(GetAccountPasswordPolicyCommand).rejects(new Error("API Error"));

			const result = await checkPasswordReusePreventionCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking password policy: API Error");
		});

		it("should return ERROR with custom error message", async () => {
			mockIAMClient.on(GetAccountPasswordPolicyCommand).rejects({
				name: "AccessDenied",
				message: "User is not authorized"
			});

			const result = await checkPasswordReusePreventionCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("User is not authorized");
		});
	});
});
