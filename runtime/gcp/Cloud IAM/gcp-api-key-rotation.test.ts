// @ts-nocheck
import { ApiKeysClient } from "@google-cloud/apikeys";
import { ComplianceStatus } from "../../types.js";
import checkApiKeyRotation from "./gcp-api-key-rotation.js";

describe("checkApiKeyRotation", () => {
	beforeEach(() => {
		// Reset the mock
		ApiKeysClient.prototype.listKeys = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS for API keys less than 90 days old", async () => {
			const recentDate = new Date();
			recentDate.setDate(recentDate.getDate() - 30); // 30 days ago

			const mockKey = {
				name: "projects/test-project/locations/global/keys/test-key-1",
				createTime: recentDate.toISOString()
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyRotation.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe(mockKey.name);
		});

		it("should handle multiple compliant API keys", async () => {
			const recentDate = new Date();
			recentDate.setDate(recentDate.getDate() - 45); // 45 days ago

			const mockKeys = [
				{
					name: "projects/test-project/locations/global/keys/test-key-1",
					createTime: recentDate.toISOString()
				},
				{
					name: "projects/test-project/locations/global/keys/test-key-2",
					createTime: new Date().toISOString()
				}
			];

			ApiKeysClient.prototype.listKeys = async () => [mockKeys];

			const result = await checkApiKeyRotation.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for API keys older than 90 days", async () => {
			const oldDate = new Date();
			oldDate.setDate(oldDate.getDate() - 91); // 91 days ago

			const mockKey = {
				name: "projects/test-project/locations/global/keys/old-key",
				createTime: oldDate.toISOString()
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyRotation.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("has not been rotated in the last 90 days");
		});

		it("should handle mixed compliant and non-compliant keys", async () => {
			const oldDate = new Date();
			oldDate.setDate(oldDate.getDate() - 100); // 100 days ago
			const recentDate = new Date();
			recentDate.setDate(recentDate.getDate() - 30); // 30 days ago

			const mockKeys = [
				{
					name: "projects/test-project/locations/global/keys/old-key",
					createTime: oldDate.toISOString()
				},
				{
					name: "projects/test-project/locations/global/keys/new-key",
					createTime: recentDate.toISOString()
				}
			];

			ApiKeysClient.prototype.listKeys = async () => [mockKeys];

			const result = await checkApiKeyRotation.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no API keys exist", async () => {
			ApiKeysClient.prototype.listKeys = async () => [[]];

			const result = await checkApiKeyRotation.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No API keys found in the project");
		});

		it("should handle API key without createTime", async () => {
			const mockKey = {
				name: "projects/test-project/locations/global/keys/test-key"
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyRotation.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});

		it("should handle API key without name", async () => {
			const mockKey = {
				createTime: new Date().toISOString()
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyRotation.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown API Key");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			ApiKeysClient.prototype.listKeys = async () => {
				throw new Error("API Error");
			};

			const result = await checkApiKeyRotation.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking API key rotation: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			ApiKeysClient.prototype.listKeys = async () => {
				throw "Unknown error";
			};

			const result = await checkApiKeyRotation.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking API key rotation: Unknown error");
		});

		it("should handle missing project ID", async () => {
			const result = await checkApiKeyRotation.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No API keys found in the project");
		});
	});
});
