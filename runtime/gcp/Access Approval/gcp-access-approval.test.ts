// @ts-nocheck
import { AccessApprovalClient } from "@google-cloud/access-approval";
import { ComplianceStatus } from "../../types.js";
import checkAccessApprovalEnabled from "./gcp-access-approval.js";

describe("checkAccessApprovalEnabled", () => {
	beforeEach(() => {
		// Reset the mock
		AccessApprovalClient.prototype.getAccessApprovalSettings = async () => [{}];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Access Approval is properly configured", async () => {
			const mockSettings = {
				name: "projects/test-project/accessApprovalSettings",
				enrolledServices: [
					{
						cloudProduct: "all",
						enrollmentLevel: "BLOCK_ALL"
					}
				],
				notificationEmails: ["security@example.com"]
			};

			AccessApprovalClient.prototype.getAccessApprovalSettings = async () => [mockSettings];

			const result = await checkAccessApprovalEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("projects/test-project/accessApprovalSettings");
		});

		it("should handle multiple notification emails", async () => {
			const mockSettings = {
				name: "projects/test-project/accessApprovalSettings",
				enrolledServices: [
					{
						cloudProduct: "all",
						enrollmentLevel: "BLOCK_ALL"
					}
				],
				notificationEmails: ["security@example.com", "admin@example.com"]
			};

			AccessApprovalClient.prototype.getAccessApprovalSettings = async () => [mockSettings];

			const result = await checkAccessApprovalEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Access Approval is not enabled", async () => {
			AccessApprovalClient.prototype.getAccessApprovalSettings = async () => [null];

			const result = await checkAccessApprovalEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("Access Approval is not enabled for the project");
		});

		it("should return FAIL when enrolled services are not properly configured", async () => {
			const mockSettings = {
				name: "projects/test-project/accessApprovalSettings",
				enrolledServices: [
					{
						cloudProduct: "storage",
						enrollmentLevel: "BLOCK_ALL"
					}
				],
				notificationEmails: ["security@example.com"]
			};

			AccessApprovalClient.prototype.getAccessApprovalSettings = async () => [mockSettings];

			const result = await checkAccessApprovalEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain(
				"Access Approval must be enabled with proper configuration"
			);
		});

		it("should return FAIL when notification emails are not configured", async () => {
			const mockSettings = {
				name: "projects/test-project/accessApprovalSettings",
				enrolledServices: [
					{
						cloudProduct: "all",
						enrollmentLevel: "BLOCK_ALL"
					}
				],
				notificationEmails: []
			};

			AccessApprovalClient.prototype.getAccessApprovalSettings = async () => [mockSettings];

			const result = await checkAccessApprovalEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should handle missing project ID", async () => {
			const result = await checkAccessApprovalEnabled.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});

		it("should handle undefined settings name", async () => {
			const mockSettings = {
				enrolledServices: [
					{
						cloudProduct: "all",
						enrollmentLevel: "BLOCK_ALL"
					}
				],
				notificationEmails: ["security@example.com"]
			};

			AccessApprovalClient.prototype.getAccessApprovalSettings = async () => [mockSettings];

			const result = await checkAccessApprovalEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceArn).toBeUndefined();
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			AccessApprovalClient.prototype.getAccessApprovalSettings = async () => {
				throw new Error("API Error");
			};

			const result = await checkAccessApprovalEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking Access Approval settings: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			AccessApprovalClient.prototype.getAccessApprovalSettings = async () => {
				throw "Unknown error";
			};

			const result = await checkAccessApprovalEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking Access Approval settings: Unknown error"
			);
		});
	});
});
