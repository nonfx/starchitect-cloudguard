import { IAMClient, GetAccountPasswordPolicyCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkPasswordPolicyLength from "./aws_iam_account_password_policy";

const mockIAMClient = mockClient(IAMClient);

describe("checkPasswordPolicyLength", () => {
    beforeEach(() => {
        mockIAMClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when password length is 14", async () => {
            mockIAMClient.on(GetAccountPasswordPolicyCommand).resolves({
                PasswordPolicy: {
                    MinimumPasswordLength: 14
                }
            });

            const result = await checkPasswordPolicyLength.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("Password Policy");
            expect(result.checks[0].message).toBeUndefined();
        });

        it("should return PASS when password length is greater than 14", async () => {
            mockIAMClient.on(GetAccountPasswordPolicyCommand).resolves({
                PasswordPolicy: {
                    MinimumPasswordLength: 16
                }
            });

            const result = await checkPasswordPolicyLength.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("Password Policy");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when password length is less than 14", async () => {
            mockIAMClient.on(GetAccountPasswordPolicyCommand).resolves({
                PasswordPolicy: {
                    MinimumPasswordLength: 8
                }
            });

            const result = await checkPasswordPolicyLength.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Password policy minimum length is 8, which is less than the required 14 characters");
        });

        it("should return FAIL when password policy is not configured", async () => {
            mockIAMClient.on(GetAccountPasswordPolicyCommand).resolves({
                PasswordPolicy: null
            });

            const result = await checkPasswordPolicyLength.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("No password policy is configured");
        });

        it("should return FAIL when NoSuchEntityException is thrown", async () => {
            const error = new Error("The specified policy does not exist");
            error.name = "NoSuchEntityException";
            mockIAMClient.on(GetAccountPasswordPolicyCommand).rejects(error);

            const result = await checkPasswordPolicyLength.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("No password policy is configured");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockIAMClient.on(GetAccountPasswordPolicyCommand).rejects(new Error("Internal Server Error"));

            const result = await checkPasswordPolicyLength.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Error checking password policy: Internal Server Error");
        });

        it("should handle non-Error objects in catch block", async () => {
            mockIAMClient.on(GetAccountPasswordPolicyCommand).rejects("Unknown error");

            const result = await checkPasswordPolicyLength.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Error checking password policy: Unknown error");
        });
    });
});