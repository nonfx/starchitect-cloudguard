// @ts-nocheck
import { AlertPolicyServiceClient, protos } from "@google-cloud/monitoring";
import { v2 } from "@google-cloud/logging";
import { ComplianceStatus } from "../../types.js";
import checkAuditConfigChangesMonitoring from "./check-audit-config-changes-monitoring.js";

describe("checkAuditConfigChangesMonitoring", () => {
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
				name: "projects/test-project/metrics/audit-config-changes",
				filter:
					'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*',
				labelExtractors: {},
				valueExtractor: "",
				bucketOptions: null,
				createTime: {
					seconds: "1737348538",
					nanos: 59758449
				},
				updateTime: {
					seconds: "1737348538",
					nanos: 59758449
				},
				version: "V2",
				disabled: false,
				metricDescriptor: {
					name: "projects/test-project/metricDescriptors/logging.googleapis.com/user/audit-config-changes",
					metricKind: "DELTA",
					valueType: "INT64",
					unit: "1",
					description: "",
					type: "logging.googleapis.com/user/audit-config-changes"
				}
			};

			const mockAlertPolicy = {
				displayName: "Audit Config Changes Alert",
				conditions: [
					{
						displayName: "Audit Config Changes",
						conditionThreshold: {
							filter: 'metric.type="logging.googleapis.com/user/audit-config-changes"',
							comparison: "COMPARISON_GT",
							thresholdValue: 0,
							duration: {
								seconds: "0",
								nanos: 0
							},
							trigger: {
								count: 1,
								type: "count"
							}
						}
					}
				],
				enabled: {
					value: true
				}
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[mockAlertPolicy]]);

			const result = await checkAuditConfigChangesMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe(
				"Valid metric filter and alert policy found for audit configuration changes"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when metric filter is missing", async () => {
			mockListLogMetrics.mockResolvedValueOnce([[]]);

			const result = await checkAuditConfigChangesMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No metric filter found for audit configuration changes"
			);
		});

		it("should return FAIL when alert policy is missing", async () => {
			const mockMetric = {
				name: "projects/test-project/metrics/audit-config-changes",
				filter:
					'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*',
				labelExtractors: {},
				valueExtractor: "",
				bucketOptions: null,
				version: "V2",
				metricDescriptor: {
					name: "projects/test-project/metricDescriptors/logging.googleapis.com/user/audit-config-changes",
					metricKind: "DELTA",
					valueType: "INT64",
					unit: "1",
					type: "logging.googleapis.com/user/audit-config-changes"
				}
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[]]);

			const result = await checkAuditConfigChangesMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No valid alert policy found for audit configuration changes"
			);
		});

		it("should return FAIL when alert policy has incorrect configuration", async () => {
			const mockMetric = {
				name: "projects/test-project/metrics/audit-config-changes",
				filter:
					'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*',
				labelExtractors: {},
				valueExtractor: "",
				bucketOptions: null,
				version: "V2",
				metricDescriptor: {
					name: "projects/test-project/metricDescriptors/logging.googleapis.com/user/audit-config-changes",
					metricKind: "DELTA",
					valueType: "INT64",
					unit: "1",
					type: "logging.googleapis.com/user/audit-config-changes"
				}
			};

			const mockAlertPolicy = {
				displayName: "Wrong Alert",
				conditions: [
					{
						displayName: "Wrong Condition",
						conditionThreshold: {
							filter: 'metric.type="logging.googleapis.com/user/wrong-metric"',
							comparison: "COMPARISON_LT",
							thresholdValue: 1,
							duration: {
								seconds: "60",
								nanos: 0
							}
						}
					}
				]
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[mockAlertPolicy]]);

			const result = await checkAuditConfigChangesMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No valid alert policy found for audit configuration changes"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when listLogMetrics fails", async () => {
			mockListLogMetrics.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkAuditConfigChangesMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking audit config monitoring");
		});

		it("should return ERROR when listAlertPolicies fails", async () => {
			const mockMetric = {
				name: "projects/test-project/metrics/audit-config-changes",
				filter:
					'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*',
				labelExtractors: {},
				valueExtractor: "",
				bucketOptions: null,
				version: "V2",
				metricDescriptor: {
					name: "projects/test-project/metricDescriptors/logging.googleapis.com/user/audit-config-changes",
					metricKind: "DELTA",
					valueType: "INT64",
					unit: "1",
					type: "logging.googleapis.com/user/audit-config-changes"
				}
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkAuditConfigChangesMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking audit config monitoring");
		});
	});
});
