// @ts-nocheck
import { FirewallsClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkSSHRestrictions, { hasUnrestrictedSSH, isPortInRange } from "./gcp_ssh_restricted.js";

describe("checkSSHRestrictions", () => {
	beforeEach(() => {
		// Reset the mock
		FirewallsClient.prototype.list = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when SSH access is properly restricted", async () => {
			const mockRule = {
				name: "restricted-ssh",
				selfLink: "projects/test-project/global/firewalls/restricted-ssh",
				direction: "INGRESS",
				sourceRanges: ["192.168.0.0/24"],
				allowed: [
					{
						IPProtocol: "tcp",
						ports: ["22"]
					}
				]
			};

			FirewallsClient.prototype.list = async () => [[mockRule]];

			const result = await checkSSHRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("restricted-ssh");
		});

		it("should handle multiple compliant firewall rules", async () => {
			const mockRules = [
				{
					name: "rule-1",
					direction: "INGRESS",
					sourceRanges: ["10.0.0.0/8"],
					allowed: [{ IPProtocol: "tcp", ports: ["22"] }]
				},
				{
					name: "rule-2",
					direction: "EGRESS",
					sourceRanges: ["0.0.0.0/0"],
					allowed: [{ IPProtocol: "tcp", ports: ["22"] }]
				}
			];

			FirewallsClient.prototype.list = async () => [mockRules];

			const result = await checkSSHRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when SSH is open to internet", async () => {
			const mockRule = {
				name: "open-ssh",
				selfLink: "projects/test-project/global/firewalls/open-ssh",
				direction: "INGRESS",
				sourceRanges: ["0.0.0.0/0"],
				allowed: [
					{
						IPProtocol: "tcp",
						ports: ["22"]
					}
				]
			};

			FirewallsClient.prototype.list = async () => [[mockRule]];

			const result = await checkSSHRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("unrestricted SSH access");
		});

		it("should detect SSH in port ranges", async () => {
			const mockRule = {
				name: "range-ssh",
				direction: "INGRESS",
				sourceRanges: ["0.0.0.0/0"],
				allowed: [
					{
						IPProtocol: "tcp",
						ports: ["20-25"]
					}
				]
			};

			FirewallsClient.prototype.list = async () => [[mockRule]];

			const result = await checkSSHRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Helper Functions", () => {
		describe("isPortInRange", () => {
			it("should correctly identify ports in range", () => {
				expect(isPortInRange(22, "20-25")).toBe(true);
				expect(isPortInRange(22, "22-22")).toBe(true);
				expect(isPortInRange(22, "25-30")).toBe(false);
			});
		});

		describe("hasUnrestrictedSSH", () => {
			it("should identify unrestricted SSH rules", () => {
				const rule = {
					direction: "INGRESS",
					sourceRanges: ["0.0.0.0/0"],
					allowed: [{ IPProtocol: "tcp", ports: ["22"] }]
				};
				expect(hasUnrestrictedSSH(rule)).toBe(true);
			});

			it("should not flag restricted SSH rules", () => {
				const rule = {
					direction: "INGRESS",
					sourceRanges: ["192.168.0.0/24"],
					allowed: [{ IPProtocol: "tcp", ports: ["22"] }]
				};
				expect(hasUnrestrictedSSH(rule)).toBe(false);
			});
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no firewall rules exist", async () => {
			FirewallsClient.prototype.list = async () => [[]];

			const result = await checkSSHRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No firewall rules found in the project");
		});

		it("should handle rules without name", async () => {
			const mockRule = {
				direction: "INGRESS",
				sourceRanges: ["0.0.0.0/0"],
				allowed: [{ IPProtocol: "tcp", ports: ["22"] }]
			};

			FirewallsClient.prototype.list = async () => [[mockRule]];

			const result = await checkSSHRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Rule");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			FirewallsClient.prototype.list = async () => {
				throw new Error("API Error");
			};

			const result = await checkSSHRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking SSH restrictions: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			FirewallsClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkSSHRestrictions.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking SSH restrictions: Unknown error");
		});
	});
});
