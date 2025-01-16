// @ts-nocheck
import { ProjectsClient } from "@google-cloud/resource-manager";
import { ComplianceStatus } from "../../types.js";
import checkAccessTransparencyEnabled from "./gcp-access-transparency.js";

describe("checkAccessTransparencyEnabled", () => {
	beforeEach(() => {
		// Reset the mock
		ProjectsClient.prototype.getProject = async () => [{}];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Access Transparency is enabled", async () => {
			ProjectsClient.prototype.getProject = async () => [
				{
					settings: {
						accessTransparencyEnabled: true
					}
				}
			];

			const result = await checkAccessTransparencyEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("Project test-project");
		});

		it("should handle project with all settings enabled", async () => {
			ProjectsClient.prototype.getProject = async () => [
				{
					settings: {
						accessTransparencyEnabled: true,
						otherSetting: true
					}
				}
			];

			const result = await checkAccessTransparencyEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Access Transparency is disabled", async () => {
			ProjectsClient.prototype.getProject = async () => [
				{
					settings: {
						accessTransparencyEnabled: false
					}
				}
			];

			const result = await checkAccessTransparencyEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("Access Transparency is not enabled for the project");
		});

		it("should return FAIL when settings are missing", async () => {
			ProjectsClient.prototype.getProject = async () => [
				{
					settings: {}
				}
			];

			const result = await checkAccessTransparencyEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return ERROR when project ID is not provided", async () => {
			const result = await checkAccessTransparencyEnabled.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});

		it("should handle undefined project settings", async () => {
			ProjectsClient.prototype.getProject = async () => [{}];

			const result = await checkAccessTransparencyEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle null project settings", async () => {
			ProjectsClient.prototype.getProject = async () => [
				{
					settings: null
				}
			];

			const result = await checkAccessTransparencyEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			ProjectsClient.prototype.getProject = async () => {
				throw new Error("API Error");
			};

			const result = await checkAccessTransparencyEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking Access Transparency: Failed to check Access Transparency status: API Error"
			);
		});

		it("should handle non-Error exceptions", async () => {
			ProjectsClient.prototype.getProject = async () => {
				throw "Unknown error";
			};

			const result = await checkAccessTransparencyEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking Access Transparency: Failed to check Access Transparency status: Unknown error"
			);
		});

		it("should handle unexpected API response format", async () => {
			ProjectsClient.prototype.getProject = async () => [null];

			const result = await checkAccessTransparencyEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});
});
