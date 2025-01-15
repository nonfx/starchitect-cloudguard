// @ts-nocheck
import { ProjectsClient } from "@google-cloud/resource-manager";
import { ComplianceStatus } from "../../types.js";
import checkAuditLogging from "./gcp_audit_logging_configured.js";

describe("checkAuditLogging", () => {
	beforeEach(() => {
		// Reset the mock
		ProjectsClient.prototype.getIamPolicy = async () => [{}];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all required audit log types are configured", async () => {
			const mockPolicy = {
				auditConfigs: [
					{
						auditLogConfigs: [
							{ logType: "ADMIN_READ" },
							{ logType: "DATA_READ" },
							{ logType: "DATA_WRITE" }
						]
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy];

			const result = await checkAuditLogging.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("Project test-project Audit Logging");
		});

		it("should handle multiple audit configs with required types", async () => {
			const mockPolicy = {
				auditConfigs: [
					{
						auditLogConfigs: [{ logType: "ADMIN_READ" }, { logType: "DATA_READ" }]
					},
					{
						auditLogConfigs: [{ logType: "DATA_WRITE" }]
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy];

			const result = await checkAuditLogging.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when missing required audit log types", async () => {
			const mockPolicy = {
				auditConfigs: [
					{
						auditLogConfigs: [{ logType: "ADMIN_READ" }]
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy];

			const result = await checkAuditLogging.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Missing required audit log types");
		});

		it("should return FAIL when auditConfigs is empty", async () => {
			const mockPolicy = {
				auditConfigs: []
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy];

			const result = await checkAuditLogging.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should handle undefined policy", async () => {
			ProjectsClient.prototype.getIamPolicy = async () => [undefined];

			const result = await checkAuditLogging.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Unable to retrieve IAM policy");
		});

		it("should handle missing project ID", async () => {
			const result = await checkAuditLogging.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
		});

		it("should handle malformed audit configs", async () => {
			const mockPolicy = {
				auditConfigs: [
					{
						// Missing auditLogConfigs
					}
				]
			};

			ProjectsClient.prototype.getIamPolicy = async () => [mockPolicy];

			const result = await checkAuditLogging.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			ProjectsClient.prototype.getIamPolicy = async () => {
				throw new Error("API Error");
			};

			const result = await checkAuditLogging.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking audit logging configuration: API Error"
			);
		});

		it("should handle non-Error exceptions", async () => {
			ProjectsClient.prototype.getIamPolicy = async () => {
				throw "Unknown error";
			};

			const result = await checkAuditLogging.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking audit logging configuration: Unknown error"
			);
		});
	});
});
