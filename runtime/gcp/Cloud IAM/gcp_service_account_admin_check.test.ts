// @ts-nocheck
import { v2 } from "@google-cloud/iam";
import { ComplianceStatus } from "../../types.js";
import checkServiceAccountAdmin from "./gcp_service_account_admin_check.js";

describe("checkServiceAccountAdmin", () => {
	beforeEach(() => {
		// Reset the mock
		v2.PoliciesClient.prototype.getPolicy = async () => [{}];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when service accounts have non-admin roles", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/viewer",
						members: ["serviceAccount:test-sa@project.iam.gserviceaccount.com"]
					}
				]
			};

			v2.PoliciesClient.prototype.getPolicy = async () => [mockPolicy];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe(
				"serviceAccount:test-sa@project.iam.gserviceaccount.com"
			);
		});

		it("should handle multiple service accounts with compliant roles", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/viewer",
						members: [
							"serviceAccount:sa1@project.iam.gserviceaccount.com",
							"serviceAccount:sa2@project.iam.gserviceaccount.com"
						]
					}
				]
			};

			v2.PoliciesClient.prototype.getPolicy = async () => [mockPolicy];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when service account has admin role", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/owner",
						members: ["serviceAccount:admin-sa@project.iam.gserviceaccount.com"]
					}
				]
			};

			v2.PoliciesClient.prototype.getPolicy = async () => [mockPolicy];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("has administrative role");
		});

		it("should detect custom admin roles", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/customAdminRole",
						members: ["serviceAccount:custom-admin@project.iam.gserviceaccount.com"]
					}
				]
			};

			v2.PoliciesClient.prototype.getPolicy = async () => [mockPolicy];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no IAM policy exists", async () => {
			v2.PoliciesClient.prototype.getPolicy = async () => [{}];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No IAM policy bindings found");
		});

		it("should handle empty bindings", async () => {
			const mockPolicy = {
				bindings: []
			};

			v2.PoliciesClient.prototype.getPolicy = async () => [mockPolicy];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(0);
		});

		it("should handle bindings without members", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/admin"
					}
				]
			};

			v2.PoliciesClient.prototype.getPolicy = async () => [mockPolicy];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(0);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			v2.PoliciesClient.prototype.getPolicy = async () => {
				throw new Error("API Error");
			};

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking service account privileges: API Error"
			);
		});

		it("should handle non-Error exceptions", async () => {
			v2.PoliciesClient.prototype.getPolicy = async () => {
				throw "Unknown error";
			};

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking service account privileges: Unknown error"
			);
		});

		it("should handle missing project ID", async () => {
			const result = await checkServiceAccountAdmin.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
		});
	});
});
