// @ts-nocheck
import { AlertPolicyServiceClient, protos } from "@google-cloud/monitoring";
import { v2 } from "@google-cloud/logging";
import { ComplianceStatus } from "../../types.js";
import checkVpcFirewallRuleChanges from "./check-vpc-firewall-rule-changes.js";

describe("checkVpcFirewallRuleChanges", () => {
	const mockListLogMetrics = jest.fn().mockResolvedValue([[]]);
	const mockListAlertPolicies = jest.fn().mockResolvedValue([[]]);

	beforeEach(() => {
		// Reset all mocks
		mockListLogMetrics.mockClear();
		mockListAlertPolicies.mockClear();

		// Default mock implementations
		v2.MetricsServiceV2Client.prototype.listLogMetrics = mockListLogMetrics;
		AlertPolicyServiceClient.prototype.listAlertPolicies = mockListAlertPolicies;
	});

	describe("Compliant Resources", () => {
		it("should return PASS when valid metric filter and alert policy exist", async () => {
			const mockMetric = {
				name: "firewall-changes",
				filter: 'resource.type="gce_firewall_rule" AND methodName="compute.firewalls.patch"'
			};

			const mockAlertPolicy = {
				conditions: [
					{
						conditionThreshold: {
							filter: "firewall-changes",
							comparison: "COMPARISON_GT",
							thresholdValue: 0,
							duration: {
								seconds: 0,
								nanos: 0
							}
						}
					}
				]
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[mockAlertPolicy]]);

			const result = await checkVpcFirewallRuleChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe(
				"Valid metric filter and alert policy exist for VPC firewall rule changes"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when metric filter is missing", async () => {
			const mockMetric = {
				filter: 'resource.type="other_resource"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);

			const result = await checkVpcFirewallRuleChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No valid metric filter found for VPC firewall rule changes"
			);
		});

		it("should return FAIL when alert policy is missing", async () => {
			const mockMetric = {
				name: "firewall-changes",
				filter: 'resource.type="gce_firewall_rule" AND methodName="compute.firewalls.patch"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[]]);

			const result = await checkVpcFirewallRuleChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No alert policy found that monitors the firewall rule changes metric"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when listLogMetrics fails", async () => {
			mockListLogMetrics.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkVpcFirewallRuleChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking firewall rule monitoring");
		});

		it("should return ERROR when listAlertPolicies fails", async () => {
			const mockMetric = {
				name: "firewall-changes",
				filter: 'resource.type="gce_firewall_rule" AND methodName="compute.firewalls.patch"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkVpcFirewallRuleChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking firewall rule monitoring");
		});
	});
});
