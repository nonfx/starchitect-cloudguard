// @ts-nocheck
import { EssentialContactsServiceClient } from "@google-cloud/essential-contacts";
import { ComplianceStatus } from "../../types.js";
import checkEssentialContacts from "./gcp-essential-contacts.js";

describe("checkEssentialContacts", () => {
	beforeEach(() => {
		// Reset the mock
		EssentialContactsServiceClient.prototype.listContacts = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all required categories are configured with ALL", async () => {
			const mockContacts = [
				{
					email: "admin@example.com",
					notificationCategorySubscriptions: ["ALL"]
				}
			];

			EssentialContactsServiceClient.prototype.listContacts = async () => [mockContacts];

			const result = await checkEssentialContacts.execute("test-org-id");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("Organization test-org-id");
		});

		it("should return PASS when all required categories are individually configured", async () => {
			const mockContacts = [
				{
					email: "security@example.com",
					notificationCategorySubscriptions: ["SECURITY", "TECHNICAL"]
				},
				{
					email: "legal@example.com",
					notificationCategorySubscriptions: ["LEGAL", "SUSPENSION"]
				}
			];

			EssentialContactsServiceClient.prototype.listContacts = async () => [mockContacts];

			const result = await checkEssentialContacts.execute("test-org-id");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when required categories are missing", async () => {
			const mockContacts = [
				{
					email: "partial@example.com",
					notificationCategorySubscriptions: ["TECHNICAL"]
				}
			];

			EssentialContactsServiceClient.prototype.listContacts = async () => [mockContacts];

			const result = await checkEssentialContacts.execute("test-org-id");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("missing required notification categories");
		});

		it("should return FAIL when no contacts are configured", async () => {
			EssentialContactsServiceClient.prototype.listContacts = async () => [[]];

			const result = await checkEssentialContacts.execute("test-org-id");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"No essential contacts configured for the organization"
			);
		});
	});

	describe("Edge Cases", () => {
		it("should return ERROR when organization ID is not provided", async () => {
			const result = await checkEssentialContacts.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Organization ID is not provided");
		});

		it("should handle contacts without notification categories", async () => {
			const mockContacts = [
				{
					email: "incomplete@example.com"
				}
			];

			EssentialContactsServiceClient.prototype.listContacts = async () => [mockContacts];

			const result = await checkEssentialContacts.execute("test-org-id");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			EssentialContactsServiceClient.prototype.listContacts = async () => {
				throw new Error("API Error");
			};

			const result = await checkEssentialContacts.execute("test-org-id");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking essential contacts: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			EssentialContactsServiceClient.prototype.listContacts = async () => {
				throw "Unknown error";
			};

			const result = await checkEssentialContacts.execute("test-org-id");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking essential contacts: Unknown error");
		});
	});
});
