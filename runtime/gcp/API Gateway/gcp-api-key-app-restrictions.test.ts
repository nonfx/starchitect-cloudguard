// @ts-nocheck
import { ApiKeysClient } from "@google-cloud/apikeys";
import { ComplianceStatus } from "../../types.js";
import checkApiKeyAppRestrictions from "./gcp-api-key-app-restrictions.js";

describe("checkApiKeyAppRestrictions", () => {
	beforeEach(() => {
		// Reset the mock
		ApiKeysClient.prototype.listKeys = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when API key has HTTP referrer restrictions", async () => {
			const mockKey = {
				name: "test-key-1",
				restrictions: {
					browserKeyRestrictions: {
						allowedReferrers: ["https://example.com/*"]
					}
				}
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyAppRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-key-1");
		});

		it("should return PASS when API key has IP restrictions", async () => {
			const mockKey = {
				name: "test-key-2",
				restrictions: {
					serverKeyRestrictions: {
						allowedIps: ["192.168.1.0/24"]
					}
				}
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyAppRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});

		it("should return PASS when API key has mobile app restrictions", async () => {
			const mockKey = {
				name: "test-key-3",
				restrictions: {
					androidKeyRestrictions: {
						allowedApplications: [
							{
								packageName: "com.example.app",
								sha1Fingerprint: "1234567890abcdef"
							}
						]
					}
				}
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyAppRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when API key has no restrictions", async () => {
			const mockKey = {
				name: "test-key-1",
				restrictions: {}
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyAppRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("must have application restrictions configured");
		});

		it("should return FAIL when API key has wildcard HTTP referrer", async () => {
			const mockKey = {
				name: "test-key-2",
				restrictions: {
					browserKeyRestrictions: {
						allowedReferrers: ["*"]
					}
				}
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyAppRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});

		it("should return FAIL when API key has unrestricted IP range", async () => {
			const mockKey = {
				name: "test-key-3",
				restrictions: {
					serverKeyRestrictions: {
						allowedIps: ["0.0.0.0/0"]
					}
				}
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyAppRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no API keys exist", async () => {
			ApiKeysClient.prototype.listKeys = async () => [[]];

			const result = await checkApiKeyAppRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No API keys found in the project");
		});

		it("should handle API key without name", async () => {
			const mockKey = {
				restrictions: {
					browserKeyRestrictions: {
						allowedReferrers: ["https://example.com"]
					}
				}
			};

			ApiKeysClient.prototype.listKeys = async () => [[mockKey]];

			const result = await checkApiKeyAppRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown API Key");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			ApiKeysClient.prototype.listKeys = async () => {
				throw new Error("API Error");
			};

			const result = await checkApiKeyAppRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking API key application restrictions: API Error"
			);
		});

		it("should handle non-Error exceptions", async () => {
			ApiKeysClient.prototype.listKeys = async () => {
				throw "Unknown error";
			};

			const result = await checkApiKeyAppRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking API key application restrictions: Unknown error"
			);
		});
	});
});
