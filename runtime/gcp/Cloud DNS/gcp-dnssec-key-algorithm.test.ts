// @ts-nocheck
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { DNS } from "@google-cloud/dns";
import { ComplianceStatus } from "../../types.js";
import checkDNSSECKeyAlgorithm from "./gcp-dnssec-key-algorithm.js";

describe("checkDNSSECKeyAlgorithm", () => {
	beforeEach(() => {
		// Reset the mock
		DNS.prototype.getZones = async () => [[]];
	});

	afterEach(() => {
		// Clean up
		DNS.prototype.getZones = undefined;
	});

	describe("Compliant Resources", () => {
		it("should return PASS when using strong key signing algorithms", async () => {
			const mockZone = {
				metadata: {
					name: "test-zone-1",
					id: "zone-1",
					dnssecConfig: {
						state: "on",
						defaultKeySpecs: [
							{
								keyType: "keySigning",
								algorithm: "RSASHA256"
							}
						]
					}
				}
			};

			DNS.prototype.getZones = async () => [[mockZone]];

			const result = await checkDNSSECKeyAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-zone-1");
		});

		it("should handle multiple zones with strong algorithms", async () => {
			const mockZones = [
				{
					metadata: {
						name: "zone-1",
						id: "zone-1",
						dnssecConfig: {
							state: "on",
							defaultKeySpecs: [
								{
									keyType: "keySigning",
									algorithm: "ECDSAP256SHA256"
								}
							]
						}
					}
				},
				{
					metadata: {
						name: "zone-2",
						id: "zone-2",
						dnssecConfig: {
							state: "on",
							defaultKeySpecs: [
								{
									keyType: "keySigning",
									algorithm: "RSASHA512"
								}
							]
						}
					}
				}
			];

			DNS.prototype.getZones = async () => [mockZones];

			const result = await checkDNSSECKeyAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when using RSASHA1 for key signing", async () => {
			const mockZone = {
				metadata: {
					name: "test-zone-1",
					id: "zone-1",
					dnssecConfig: {
						state: "on",
						defaultKeySpecs: [
							{
								keyType: "keySigning",
								algorithm: "RSASHA1"
							}
						]
					}
				}
			};

			DNS.prototype.getZones = async () => [[mockZone]];

			const result = await checkDNSSECKeyAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("RSASHA1 is used for key signing");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no zones exist", async () => {
			DNS.prototype.getZones = async () => [[]];

			const result = await checkDNSSECKeyAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No DNS managed zones found in the project");
		});

		it("should return NOTAPPLICABLE when DNSSEC is not enabled", async () => {
			const mockZone = {
				metadata: {
					name: "test-zone-1",
					id: "zone-1",
					dnssecConfig: {
						state: "off"
					}
				}
			};

			DNS.prototype.getZones = async () => [[mockZone]];

			const result = await checkDNSSECKeyAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("DNSSEC is not enabled for this zone");
		});

		it("should handle zone without name", async () => {
			const mockZone = {
				metadata: {
					id: "zone-1",
					dnssecConfig: {
						state: "on",
						defaultKeySpecs: [
							{
								keyType: "keySigning",
								algorithm: "RSASHA256"
							}
						]
					}
				}
			};

			DNS.prototype.getZones = async () => [[mockZone]];

			const result = await checkDNSSECKeyAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Zone");
		});

		it("should return ERROR when project ID is not provided", async () => {
			const result = await checkDNSSECKeyAlgorithm.execute("");
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

			const result = await checkDNSSECKeyAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking DNSSEC key algorithms: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			DNS.prototype.getZones = async () => {
				throw "Unknown error";
			};

			const result = await checkDNSSECKeyAlgorithm.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking DNSSEC key algorithms: Unknown error");
		});
	});
});
