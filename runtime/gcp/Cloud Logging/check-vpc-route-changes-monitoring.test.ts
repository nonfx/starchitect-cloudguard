// @ts-nocheck
import { AlertPolicyServiceClient, protos } from "@google-cloud/monitoring";
import { v2 } from "@google-cloud/logging";
import { ComplianceStatus } from "../../types.js";
import checkVpcRouteChangesMonitoring from "./check-vpc-route-changes-monitoring.js";

describe("checkVpcRouteChangesMonitoring", () => {
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
		it("should return PASS when proper metric filter and alert exist", async () => {
			const validMetric = {
				name: "projects/test-project/metrics/vpc-route-changes",
				filter:
					'resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")'
			};

			const validAlert = {
				displayName: "Route Changes Alert",
				conditions: [
					{
						displayName: "Route Changes Condition",
						conditionThreshold: {
							filter: 'metric.type="logging.googleapis.com/user/vpc-route-changes"',
							comparison: "COMPARISON_GT",
							thresholdValue: 0,
							duration: {
								seconds: "0",
								nanos: 0
							}
						}
					}
				]
			};

			mockListLogMetrics.mockResolvedValueOnce([[validMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[validAlert]]);

			const result = await checkVpcRouteChangesMonitoring.execute("test-project");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no metric filters exist", async () => {
			mockListLogMetrics.mockResolvedValueOnce([[]]);

			const result = await checkVpcRouteChangesMonitoring.execute("test-project");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No metric filter exists for VPC route changes");
		});

		it("should return FAIL when metric filter has wrong pattern", async () => {
			const invalidMetric = {
				name: "projects/test-project/metrics/invalid-metric",
				filter: 'resource.type="gce_instance"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[invalidMetric]]);

			const result = await checkVpcRouteChangesMonitoring.execute("test-project");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No metric filter exists for VPC route changes");
		});

		it("should return FAIL when metric exists but no matching alert policy", async () => {
			const validMetric = {
				name: "projects/test-project/metrics/vpc-route-changes",
				filter:
					'resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")'
			};

			mockListLogMetrics.mockResolvedValueOnce([[validMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[]]);

			const result = await checkVpcRouteChangesMonitoring.execute("test-project");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No valid alert policy found for VPC route changes");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when listLogMetrics fails", async () => {
			mockListLogMetrics.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkVpcRouteChangesMonitoring.execute("test-project");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking VPC route changes monitoring");
		});

		it("should return ERROR when listAlertPolicies fails", async () => {
			const validMetric = {
				name: "projects/test-project/metrics/vpc-route-changes",
				filter:
					'resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")'
			};

			mockListLogMetrics.mockResolvedValueOnce([[validMetric]]);
			mockListAlertPolicies.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkVpcRouteChangesMonitoring.execute("test-project");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking VPC route changes monitoring");
		});
	});
});
