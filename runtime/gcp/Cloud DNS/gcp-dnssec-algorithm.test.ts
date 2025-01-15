// @ts-nocheck
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { DNS } from "@google-cloud/dns";
import { ComplianceStatus } from "../../types.js";
import checkDNSSECAlgorithm from "./gcp-dnssec-algorithm.js";

describe("checkDNSSECAlgorithm", () => {
	beforeEach(() => {
		// Reset the mock
		DNS.prototype.getZones = async () => [[]];
	});

	afterEach(() => {
		// Clean up
		DNS.prototype.getZones = undefined;
	});

	describe("Compliant Resources", () => {
		it("should return PASS when DNSSEC uses secure algorithms", async () => {
			const mockZone = {
				metadata: {
					name: "test-zone-1",
					id: "123",
					dnssecConfig: {
						state: "on",
						defaultKeySpecs: [
							{
								keyType: "zoneSigning",
								algorithm: "RSASHA256"
							}
						]
					}
				}
			};

			DNS.prototype.getZones = async () => [[mockZone]];

			const result = await checkDNSSECAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-zone-1");
		});

		it("should handle multiple zones with secure algorithms", async () => {
			const mockZones = [
				{
					metadata: {
						name: "zone-1",
						id: "123",
						dnssecConfig: {
							state: "on",
							defaultKeySpecs: [
								{
									keyType: "zoneSigning",
									algorithm: "RSASHA256"
								}
							]
						}
					}
				},
				{
					metadata: {
						name: "zone-2",
						id: "456",
						dnssecConfig: {
							state: "on",
							defaultKeySpecs: [
								{
									keyType: "zoneSigning",
									algorithm: "RSASHA512"
								}
							]
						}
					}
				}
			];

			DNS.prototype.getZones = async () => [mockZones];

			const result = await checkDNSSECAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when DNSSEC uses RSASHA1", async () => {
			const mockZone = {
				metadata: {
					name: "test-zone-1",
					id: "123",
					dnssecConfig: {
						state: "on",
						defaultKeySpecs: [
							{
								keyType: "zoneSigning",
								algorithm: "RSASHA1"
							}
						]
					}
				}
			};

			DNS.prototype.getZones = async () => [[mockZone]];

			const result = await checkDNSSECAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("using RSASHA1");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no zones exist", async () => {
			DNS.prototype.getZones = async () => [[]];

			const result = await checkDNSSECAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No DNS managed zones found in the project");
		});

		it("should return NOTAPPLICABLE when DNSSEC is not enabled", async () => {
			const mockZone = {
				metadata: {
					name: "test-zone-1",
					id: "123",
					dnssecConfig: {
						state: "off"
					}
				}
			};

			DNS.prototype.getZones = async () => [[mockZone]];

			const result = await checkDNSSECAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("DNSSEC is not enabled for this zone");
		});

		it("should handle zone without name", async () => {
			const mockZone = {
				metadata: {
					id: "123",
					dnssecConfig: {
						state: "on",
						defaultKeySpecs: [
							{
								keyType: "zoneSigning",
								algorithm: "RSASHA256"
							}
						]
					}
				}
			};

			DNS.prototype.getZones = async () => [[mockZone]];

			const result = await checkDNSSECAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Zone");
		});

		it("should return ERROR when project ID is not provided", async () => {
			const result = await checkDNSSECAlgorithm.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			DNS.prototype.getZones = async () => {
				throw new Error("API Error");
			};

			const result = await checkDNSSECAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking DNSSEC algorithm: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			DNS.prototype.getZones = async () => {
				throw "Unknown error";
			};

			const result = await checkDNSSECAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking DNSSEC algorithm: Unknown error");
		});
	});
});
