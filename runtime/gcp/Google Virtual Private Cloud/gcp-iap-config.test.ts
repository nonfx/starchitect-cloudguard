// @ts-nocheck
import { FirewallsClient, BackendServicesClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import iapComplianceCheck from "./gcp-iap-config.js";

describe("checkIAPCompliance", () => {
	const mockListFirewalls = jest.fn().mockResolvedValue([[]]);
	const mockListBackendServices = jest.fn().mockResolvedValue([[]]);

	beforeEach(() => {
		// Reset all mocks
		mockListFirewalls.mockClear();
		mockListBackendServices.mockClear();

		// Default mock implementations
		FirewallsClient.prototype.list = mockListFirewalls;
		BackendServicesClient.prototype.list = mockListBackendServices;
	});

	describe("IAP Status", () => {
		it("should return NOTAPPLICABLE when IAP is not enabled", async () => {
			mockListBackendServices.mockResolvedValueOnce([
				[
					{
						name: "backend-1",
						iap: { enabled: false }
					},
					{
						name: "backend-2",
						iap: null
					}
				]
			]);

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("IAP is not enabled for any backend services");
		});

		it("should check firewall rules when IAP is enabled", async () => {
			mockListBackendServices.mockResolvedValueOnce([
				[
					{
						name: "backend-1",
						iap: { enabled: true }
					}
				]
			]);

			const mockRule = {
				name: "compliant-rule",
				sourceRanges: ["35.235.240.0/20", "130.211.0.0/22", "35.191.0.0/16"],
				allowed: [{ IPProtocol: "tcp", ports: ["80", "443"] }]
			};

			mockListFirewalls.mockResolvedValueOnce([[mockRule]]);

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Compliant Resources", () => {
		beforeEach(() => {
			// Mock IAP enabled for all compliant tests
			mockListBackendServices.mockResolvedValue([[{ name: "backend", iap: { enabled: true } }]]);
		});

		it("should return PASS when firewall rules comply with IAP requirements", async () => {
			const mockRule = {
				name: "compliant-rule",
				selfLink: "projects/test-project/global/firewalls/compliant-rule",
				sourceRanges: [
					"35.235.240.0/20", // IAP Proxy
					"130.211.0.0/22", // Health Check
					"35.191.0.0/16" // Health Check
				],
				allowed: [
					{
						IPProtocol: "tcp",
						ports: ["80", "443"]
					}
				]
			};

			mockListFirewalls.mockResolvedValueOnce([[mockRule]]);

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("compliant-rule");
		});

		it("should handle multiple compliant rules", async () => {
			const mockRules = [
				{
					name: "rule-1",
					sourceRanges: ["35.235.240.0/20", "130.211.0.0/22", "35.191.0.0/16"],
					allowed: [{ IPProtocol: "tcp", ports: ["80", "443"] }]
				},
				{
					name: "rule-2",
					sourceRanges: ["35.235.240.0/20", "130.211.0.0/22", "35.191.0.0/16"],
					allowed: [{ IPProtocol: "tcp", ports: ["80", "443"] }]
				}
			];

			mockListFirewalls.mockResolvedValueOnce([mockRules]);

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		beforeEach(() => {
			// Mock IAP enabled for all non-compliant tests
			mockListBackendServices.mockResolvedValue([[{ name: "backend", iap: { enabled: true } }]]);
		});

		it("should return FAIL when no firewall rules exist but IAP is enabled", async () => {
			mockListFirewalls.mockResolvedValueOnce([[]]);

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("No firewall rules found but IAP is enabled");
		});

		it("should return FAIL when rule allows additional IP ranges", async () => {
			const mockRule = {
				name: "non-compliant-rule",
				sourceRanges: [
					"35.235.240.0/20",
					"130.211.0.0/22",
					"35.191.0.0/16",
					"0.0.0.0/0" // Additional non-compliant range
				],
				allowed: [{ IPProtocol: "tcp", ports: ["80", "443"] }]
			};

			mockListFirewalls.mockResolvedValueOnce([[mockRule]]);

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("does not comply with IAP requirements");
		});

		it("should return FAIL when rule allows additional ports", async () => {
			const mockRule = {
				name: "non-compliant-ports",
				sourceRanges: ["35.235.240.0/20", "130.211.0.0/22", "35.191.0.0/16"],
				allowed: [{ IPProtocol: "tcp", ports: ["80", "443", "8080"] }]
			};

			mockListFirewalls.mockResolvedValueOnce([[mockRule]]);

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});

		it("should return FAIL when rule allows non-TCP protocol", async () => {
			const mockRule = {
				name: "non-tcp-rule",
				sourceRanges: ["35.235.240.0/20", "130.211.0.0/22", "35.191.0.0/16"],
				allowed: [{ IPProtocol: "udp", ports: ["80", "443"] }]
			};

			mockListFirewalls.mockResolvedValueOnce([[mockRule]]);

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return ERROR when project ID is not provided", async () => {
			const result = await iapComplianceCheck.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is required but was not provided");
		});

		it("should handle missing sourceRanges", async () => {
			mockListBackendServices.mockResolvedValueOnce([
				[{ name: "backend", iap: { enabled: true } }]
			]);

			const mockRule = {
				name: "missing-ranges",
				allowed: [{ IPProtocol: "tcp", ports: ["80", "443"] }]
			};

			mockListFirewalls.mockResolvedValueOnce([[mockRule]]);

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle missing allowed rules", async () => {
			mockListBackendServices.mockResolvedValueOnce([
				[{ name: "backend", iap: { enabled: true } }]
			]);

			const mockRule = {
				name: "missing-allowed",
				sourceRanges: ["35.235.240.0/20", "130.211.0.0/22", "35.191.0.0/16"]
			};

			mockListFirewalls.mockResolvedValueOnce([[mockRule]]);

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should handle IAP status check errors", async () => {
			mockListBackendServices.mockRejectedValueOnce(new Error("IAP Status Error"));

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Failed to check IAP status");
		});

		it("should handle firewall list errors", async () => {
			mockListBackendServices.mockResolvedValueOnce([
				[{ name: "backend", iap: { enabled: true } }]
			]);
			mockListFirewalls.mockRejectedValueOnce(new Error("API Error"));

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking IAP compliance: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockListBackendServices.mockResolvedValueOnce([
				[{ name: "backend", iap: { enabled: true } }]
			]);
			mockListFirewalls.mockRejectedValueOnce("Unknown error");

			const result = await iapComplianceCheck.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking IAP compliance: Unknown error");
		});
	});
});
