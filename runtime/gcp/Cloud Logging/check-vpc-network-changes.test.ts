// @ts-nocheck
import { AlertPolicyServiceClient, protos } from "@google-cloud/monitoring";
import { v2 } from "@google-cloud/logging";
import { ComplianceStatus } from "../../types.js";
import checkVpcNetworkChanges from "./check-vpc-network-changes.js";

describe("checkVpcNetworkChanges", () => {
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
				name: "projects/test-project/metrics/vpc-network-metric",
				filter: 'resource.type="gce_network" AND methodName="compute.networks.insert"'
			};

			const mockAlertPolicy = {
				conditions: [
					{
						displayName: "VPC Network Changes",
						conditionThreshold: {
							filter: "projects/test-project/metrics/vpc-network-metric",
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

			const result = await checkVpcNetworkChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe(
				"Valid metric filter and alert policy exist for VPC network changes"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when metric filter is missing", async () => {
			mockListLogMetrics.mockResolvedValueOnce([[]]);

			const result = await checkVpcNetworkChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No metric filter found for VPC network changes");
		});

		it("should return FAIL when metric filter has wrong pattern", async () => {
			const mockMetric = {
				name: "projects/test-project/metrics/vpc-network-metric",
				filter: 'resource.type="gce_instance"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);

			const result = await checkVpcNetworkChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No metric filter found for VPC network changes");
		});

		it("should return FAIL when alert policy is missing", async () => {
			const mockMetric = {
				name: "projects/test-project/metrics/vpc-network-metric",
				filter: 'resource.type="gce_network" AND methodName="compute.networks.insert"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[]]);

			const result = await checkVpcNetworkChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No valid alert policy found for VPC network changes");
		});

		it("should return FAIL when alert policy has incorrect configuration", async () => {
			const mockMetric = {
				name: "projects/test-project/metrics/vpc-network-metric",
				filter: 'resource.type="gce_network" AND methodName="compute.networks.insert"'
			};

			const mockAlertPolicy = {
				conditions: [
					{
						displayName: "Wrong Policy",
						conditionThreshold: {
							filter: "wrong-metric",
							comparison: "COMPARISON_LT",
							thresholdValue: 1,
							duration: {
								seconds: 60,
								nanos: 0
							}
						}
					}
				]
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[mockAlertPolicy]]);

			const result = await checkVpcNetworkChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No valid alert policy found for VPC network changes");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when listLogMetrics fails", async () => {
			mockListLogMetrics.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkVpcNetworkChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking VPC network changes monitoring");
		});

		it("should return FAIL when listAlertPolicies fails", async () => {
			const mockMetric = {
				name: "projects/test-project/metrics/vpc-network-metric",
				filter: 'resource.type="gce_network" AND methodName="compute.networks.insert"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkVpcNetworkChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking VPC network changes monitoring");
		});
	});
});
