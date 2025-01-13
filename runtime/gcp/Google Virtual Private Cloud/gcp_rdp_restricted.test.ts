// @ts-nocheck
import { FirewallsClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkRDPRestrictions, { hasUnrestrictedRDP, isPortInRange } from "./gcp_rdp_restricted.js";

describe("checkRDPRestrictions", () => {
	beforeEach(() => {
		// Reset the mock
		FirewallsClient.prototype.list = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when RDP access is properly restricted", async () => {
			const mockRule = {
				name: "restricted-rdp",
				selfLink: "projects/test-project/global/firewalls/restricted-rdp",
				direction: "INGRESS",
				sourceRanges: ["192.168.0.0/24"],
				allowed: [
					{
						IPProtocol: "tcp",
						ports: ["3389"]
					}
				]
			};

			FirewallsClient.prototype.list = async () => [[mockRule]];

			const result = await checkRDPRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("restricted-rdp");
		});

		it("should handle multiple compliant firewall rules", async () => {
			const mockRules = [
				{
					name: "rule-1",
					direction: "INGRESS",
					sourceRanges: ["10.0.0.0/8"],
					allowed: [{ IPProtocol: "tcp", ports: ["3389"] }]
				},
				{
					name: "rule-2",
					direction: "EGRESS",
					sourceRanges: ["0.0.0.0/0"],
					allowed: [{ IPProtocol: "tcp", ports: ["3389"] }]
				}
			];

			FirewallsClient.prototype.list = async () => [mockRules];

			const result = await checkRDPRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when RDP is open to internet", async () => {
			const mockRule = {
				name: "open-rdp",
				selfLink: "projects/test-project/global/firewalls/open-rdp",
				direction: "INGRESS",
				sourceRanges: ["0.0.0.0/0"],
				allowed: [
					{
						IPProtocol: "tcp",
						ports: ["3389"]
					}
				]
			};

			FirewallsClient.prototype.list = async () => [[mockRule]];

			const result = await checkRDPRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("unrestricted RDP access");
		});

		it("should detect RDP in port ranges", async () => {
			const mockRule = {
				name: "range-rdp",
				direction: "INGRESS",
				sourceRanges: ["0.0.0.0/0"],
				allowed: [
					{
						IPProtocol: "tcp",
						ports: ["3000-4000"]
					}
				]
			};

			FirewallsClient.prototype.list = async () => [[mockRule]];

			const result = await checkRDPRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Helper Functions", () => {
		describe("isPortInRange", () => {
			it("should correctly identify ports in range", () => {
				expect(isPortInRange(3389, "3000-4000")).toBe(true);
				expect(isPortInRange(3389, "3389-3389")).toBe(true);
				expect(isPortInRange(3389, "1000-2000")).toBe(false);
			});
		});

		describe("hasUnrestrictedRDP", () => {
			it("should identify unrestricted RDP rules", () => {
				const rule = {
					direction: "INGRESS",
					sourceRanges: ["0.0.0.0/0"],
					allowed: [{ IPProtocol: "tcp", ports: ["3389"] }]
				};
				expect(hasUnrestrictedRDP(rule)).toBe(true);
			});

			it("should not flag restricted RDP rules", () => {
				const rule = {
					direction: "INGRESS",
					sourceRanges: ["192.168.0.0/24"],
					allowed: [{ IPProtocol: "tcp", ports: ["3389"] }]
				};
				expect(hasUnrestrictedRDP(rule)).toBe(false);
			});
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no firewall rules exist", async () => {
			FirewallsClient.prototype.list = async () => [[]];

			const result = await checkRDPRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No firewall rules found in the project");
		});

		it("should handle rules without name", async () => {
			const mockRule = {
				direction: "INGRESS",
				sourceRanges: ["0.0.0.0/0"],
				allowed: [{ IPProtocol: "tcp", ports: ["3389"] }]
			};

			FirewallsClient.prototype.list = async () => [[mockRule]];

			const result = await checkRDPRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Rule");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			FirewallsClient.prototype.list = async () => {
				throw new Error("API Error");
			};

			const result = await checkRDPRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking RDP restrictions: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			FirewallsClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkRDPRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking RDP restrictions: Unknown error");
		});
	});
});
