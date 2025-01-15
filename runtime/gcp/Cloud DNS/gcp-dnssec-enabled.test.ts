// @ts-nocheck
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { DNS } from "@google-cloud/dns";
import { ComplianceStatus } from "../../types.js";
import checkDnssecEnabled from "./gcp-dnssec-enabled.js";

describe("checkDnssecEnabled", () => {
	let mockGetZones;

	beforeEach(() => {
		// Create mock functions
		mockGetZones = () => Promise.resolve([[]]);

		// Mock the DNS class
		DNS.prototype.getZones = mockGetZones;
	});

	afterEach(() => {
		// Reset mocks
		DNS.prototype.getZones = undefined;
	});

	describe("Compliant Resources", () => {
		it("should return PASS when DNSSEC is enabled on public zone", async () => {
			const mockZone = {
				metadata: {
					name: "test-zone",
					id: "123",
					visibility: "public",
					dnssecConfig: {
						state: "on"
					}
				}
			};

			DNS.prototype.getZones = () => Promise.resolve([[mockZone]]);

			const result = await checkDnssecEnabled.execute("test-project");
			expect(result.checks.length).toBe(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-zone");
			expect(result.checks[0]?.resourceArn).toBe("projects/test-project/managedZones/123");
		});

		it("should handle multiple zones with different configurations", async () => {
			const mockZones = [
				{
					metadata: {
						name: "public-zone-enabled",
						id: "123",
						visibility: "public",
						dnssecConfig: { state: "on" }
					}
				},
				{
					metadata: {
						name: "public-zone-disabled",
						id: "456",
						visibility: "public",
						dnssecConfig: { state: "off" }
					}
				},
				{
					metadata: {
						name: "private-zone",
						id: "789",
						visibility: "private"
					}
				}
			];

			DNS.prototype.getZones = () => Promise.resolve([mockZones]);

			const result = await checkDnssecEnabled.execute("test-project");
			expect(result.checks.length).toBe(3);

			// Check public zone with DNSSEC enabled
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("public-zone-enabled");

			// Check public zone with DNSSEC disabled
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1]?.resourceName).toBe("public-zone-disabled");
			expect(result.checks[1]?.message).toContain("DNSSEC is not enabled");

			// Check private zone
			expect(result.checks[2]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[2]?.message).toBe("Zone is not public");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when DNSSEC is disabled on public zone", async () => {
			const mockZone = {
				metadata: {
					name: "test-zone",
					id: "123",
					visibility: "public",
					dnssecConfig: {
						state: "off"
					}
				}
			};

			DNS.prototype.getZones = () => Promise.resolve([[mockZone]]);

			const result = await checkDnssecEnabled.execute("test-project");
			expect(result.checks.length).toBe(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("DNSSEC is not enabled");
			expect(result.checks[0]?.message).toContain("gcloud dns managed-zones update");
		});

		it("should return FAIL when DNSSEC configuration is missing", async () => {
			const mockZone = {
				metadata: {
					name: "test-zone",
					id: "123",
					visibility: "public"
				}
			};

			DNS.prototype.getZones = () => Promise.resolve([[mockZone]]);

			const result = await checkDnssecEnabled.execute("test-project");
			expect(result.checks.length).toBe(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no zones exist", async () => {
			DNS.prototype.getZones = () => Promise.resolve([[]]);

			const result = await checkDnssecEnabled.execute("test-project");
			expect(result.checks.length).toBe(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No DNS zones found in the project");
		});

		it("should return ERROR when project ID is not provided", async () => {
			const result = await checkDnssecEnabled.execute("");
			expect(result.checks.length).toBe(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});

		it("should handle zones with missing metadata", async () => {
			const mockZone = {};
			DNS.prototype.getZones = () => Promise.resolve([[mockZone]]);

			const result = await checkDnssecEnabled.execute("test-project");
			expect(result.checks.length).toBe(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Zone");
		});
	});

	describe("Error Handling", () => {
		it("should handle permission denied errors", async () => {
			DNS.prototype.getZones = () => Promise.reject(new Error("permission denied"));

			const result = await checkDnssecEnabled.execute("test-project");
			expect(result.checks.length).toBe(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Insufficient permissions");
		});

		it("should handle API errors", async () => {
			DNS.prototype.getZones = () => Promise.reject(new Error("API Error"));

			const result = await checkDnssecEnabled.execute("test-project");
			expect(result.checks.length).toBe(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking DNSSEC status");
		});

		it("should handle non-Error exceptions", async () => {
			DNS.prototype.getZones = () => Promise.reject("Unknown error");

			const result = await checkDnssecEnabled.execute("test-project");
			expect(result.checks.length).toBe(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Unknown error");
		});
	});
});
