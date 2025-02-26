// @ts-nocheck
import { AccountClient, GetAlternateContactCommand } from "@aws-sdk/client-account";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkSecurityContact from "./check-security-contact";

const mockAccountClient = mockClient(AccountClient);

describe("checkSecurityContact", () => {
	beforeEach(() => {
		mockAccountClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when security contact is configured", async () => {
			mockAccountClient.on(GetAlternateContactCommand).resolves({
				AlternateContact: {
					EmailAddress: "security@example.com",
					Name: "Security Team",
					PhoneNumber: "+1234567890",
					Title: "Security Contact"
				}
			});

			const result = await checkSecurityContact.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("Account Security Contact");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no security contact is configured", async () => {
			mockAccountClient.on(GetAlternateContactCommand).rejects({
				name: "ResourceNotFoundException",
				message: "Alternate contact not found"
			});

			const result = await checkSecurityContact.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No security contact information is configured for the AWS account"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails with unexpected error", async () => {
			mockAccountClient.on(GetAlternateContactCommand).rejects(new Error("Internal Server Error"));

			const result = await checkSecurityContact.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking security contact");
		});

		it("should return ERROR when API call fails with access denied", async () => {
			mockAccountClient.on(GetAlternateContactCommand).rejects({
				name: "AccessDeniedException",
				message: "User is not authorized"
			});

			const result = await checkSecurityContact.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking security contact");
		});
	});

	describe("Region Handling", () => {
		it("should use default region when none provided", async () => {
			mockAccountClient.on(GetAlternateContactCommand).resolves({
				AlternateContact: {
					EmailAddress: "security@example.com",
					Name: "Security Team"
				}
			});

			const result = await checkSecurityContact.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});
});
