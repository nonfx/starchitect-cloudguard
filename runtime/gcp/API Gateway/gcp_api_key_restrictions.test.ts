// @ts-nocheck
import { ApiKeysClient } from "@google-cloud/apikeys";
import { ComplianceStatus } from "../../types.js";
import checkApiKeyRestrictions from "./gcp_api_key_restrictions.js";

describe("checkApiKeyRestrictions", () => {
	beforeEach(() => {
		// Reset the mock
		ApiKeysClient.prototype.listKeys = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when API key has proper restrictions", async () => {
			const mockKey = {
				name: "test-key-1",
				restrictions: [
					{
						apiTargets: [
							{
								service: "storage.googleapis.com"
							}
						]
					}
				]
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-key-1");
		});

		it("should handle multiple API keys with restrictions", async () => {
			const mockKeys = [
				{
					name: "test-key-1",
					restrictions: [
						{
							apiTargets: [
								{
									service: "storage.googleapis.com"
								}
							]
						}
					]
				},
				{
					name: "test-key-2",
					restrictions: [
						{
							apiTargets: [
								{
									service: "compute.googleapis.com"
								}
							]
						}
					]
				}
			];

			ApiKeysClient.prototype.listKeys = async () => [mockKeys];

			const result = await checkApiKeyRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when API key has no restrictions", async () => {
			const mockKey = {
				name: "test-key-1",
				restrictions: []
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"API key must have API target restrictions configured to limit access to only required APIs"
			);
		});

		it("should return FAIL when API key has empty API targets", async () => {
			const mockKey = {
				name: "test-key-1",
				restrictions: [
					{
						apiTargets: []
					}
				]
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no API keys exist", async () => {
			ApiKeysClient.prototype.listKeys = async () => [[]];

			const result = await checkApiKeyRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No API keys found in the project");
		});

		it("should handle API key without name", async () => {
			const mockKey = {
				restrictions: [
					{
						apiTargets: [
							{
								service: "storage.googleapis.com"
							}
						]
					}
				]
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown API Key");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			ApiKeysClient.prototype.listKeys = async () => {
				throw new Error("API Error");
			};

			const result = await checkApiKeyRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking API key restrictions: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			ApiKeysClient.prototype.listKeys = async () => {
				throw "Unknown error";
			};

			const result = await checkApiKeyRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking API key restrictions: Unknown error");
		});
	});
});
