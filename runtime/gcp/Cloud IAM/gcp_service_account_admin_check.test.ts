// @ts-nocheck
import { ProjectsClient } from "@google-cloud/resource-manager";
import { ComplianceStatus } from "../../types.js";
import checkServiceAccountAdmin from "./gcp_service_account_admin_check.js";

describe("checkServiceAccountAdmin", () => {
	beforeEach(() => {
		// Reset the mock
		ProjectsClient.prototype.getIamPolicy = async () => [{}, undefined, {}];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when user-managed service accounts have non-admin roles", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/viewer",
						members: ["serviceAccount:test-sa@test-project.iam.gserviceaccount.com"]
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy, undefined, {}];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-sa@test-project.iam.gserviceaccount.com");
		});

		it("should ignore Google-managed service accounts with admin roles", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/owner",
						members: [
							"serviceAccount:123456789-compute@developer.gserviceaccount.com",
							"serviceAccount:test-app@appspot.gserviceaccount.com",
							"serviceAccount:service@cloudservices.gserviceaccount.com",
							"serviceAccount:system@system.gserviceaccount.com"
						]
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy, undefined, {}];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe(
				"No user-managed service accounts found in the project"
			);
		});

		it("should handle multiple service accounts with compliant roles", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/viewer",
						members: [
							"serviceAccount:sa1@test-project.iam.gserviceaccount.com",
							"serviceAccount:sa2@test-project.iam.gserviceaccount.com"
						]
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy, undefined, {}];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when service account has owner role", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/owner",
						members: ["serviceAccount:admin-sa@test-project.iam.gserviceaccount.com"]
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy, undefined, {}];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("roles/owner");
		});

		it("should return FAIL when service account has editor role", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/editor",
						members: ["serviceAccount:editor-sa@test-project.iam.gserviceaccount.com"]
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy, undefined, {}];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("roles/editor");
		});

		it("should detect custom admin roles", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/customAdminRole",
						members: ["serviceAccount:custom-admin@test-project.iam.gserviceaccount.com"]
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy, undefined, {}];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("roles/customAdminRole");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no IAM policy exists", async () => {
			ProjectsClient.prototype.getIamPolicy = async () => [{}, undefined, {}];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No IAM policy bindings found");
		});

		it("should handle empty bindings", async () => {
			const mockPolicy = {
				bindings: []
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy, undefined, {}];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe(
				"No user-managed service accounts found in the project"
			);
		});

		it("should handle bindings without members", async () => {
			const mockPolicy = {
				bindings: [
					{
						role: "roles/admin"
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy, undefined, {}];

			const result = await checkServiceAccountAdmin.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe(
				"No user-managed service accounts found in the project"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			ProjectsClient.prototype.getIamPolicy = async () => {
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
			ProjectsClient.prototype.getIamPolicy = async () => {
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
			expect(result.checks[0]?.message).toBe("Missing required project ID");
		});
	});
});
