// @ts-nocheck
import { ApiKeysClient } from "@google-cloud/apikeys";
import { ComplianceStatus } from "../../types.js";
import checkActiveApiKeys from "./gcp-active-api-keys.js";

describe("checkActiveApiKeys", () => {
	beforeEach(() => {
		// Reset the mock
		ApiKeysClient.prototype.listKeys = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS for active API keys", async () => {
			const mockKey = {
				name: "projects/test-project/locations/global/keys/test-key-1",
				displayName: "test-key-1",
				keyString: "AIzaSyA1234567890",
				deleted: false
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkActiveApiKeys.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe(
				"projects/test-project/locations/global/keys/test-key-1"
			);
		});

		it("should handle multiple active API keys", async () => {
			const mockKeys = [
				{
					name: "projects/test-project/locations/global/keys/key-1",
					displayName: "key-1",
					keyString: "AIzaSyA1234567890",
					deleted: false
				},
				{
					name: "projects/test-project/locations/global/keys/key-2",
					displayName: "key-2",
					keyString: "AIzaSyB1234567890",
					deleted: false
				}
			];

			ApiKeysClient.prototype.listKeys = async () => [mockKeys];

			const result = await checkActiveApiKeys.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for deleted API keys", async () => {
			const mockKey = {
				name: "projects/test-project/locations/global/keys/deleted-key",
				displayName: "deleted-key",
				keyString: "AIzaSyC1234567890",
				deleted: true
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkActiveApiKeys.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Inactive or deleted API key detected");
		});

		it("should return FAIL for keys without keyString", async () => {
			const mockKey = {
				name: "projects/test-project/locations/global/keys/invalid-key",
				displayName: "invalid-key",
				deleted: false
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkActiveApiKeys.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return PASS when no API keys exist", async () => {
			ApiKeysClient.prototype.listKeys = async () => [[]];

			const result = await checkActiveApiKeys.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.message).toBe("No API keys found in the project");
		});

		it("should handle API key without name", async () => {
			const mockKey = {
				displayName: "unnamed-key",
				keyString: "AIzaSyD1234567890",
				deleted: false
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkActiveApiKeys.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown API Key");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			ApiKeysClient.prototype.listKeys = async () => {
				throw new Error("API Error");
			};

			const result = await checkActiveApiKeys.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking API key activity: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			ApiKeysClient.prototype.listKeys = async () => {
				throw "Unknown error";
			};

			const result = await checkActiveApiKeys.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking API key activity: Unknown error");
		});

		it("should handle missing project ID", async () => {
			const result = await checkActiveApiKeys.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
		});
	});
});
