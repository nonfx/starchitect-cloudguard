// @ts-nocheck
import { AlertPolicyServiceClient, protos } from "@google-cloud/monitoring";
import { v2 } from "@google-cloud/logging";
import { ComplianceStatus } from "../../types.js";
import checkProjectOwnershipMonitoring from "./check-project-ownership-monitoring.js";

describe("checkProjectOwnershipMonitoring", () => {
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
				name: "ownership-changes",
				filter:
					'resource.type="project" AND ' +
					'protoPayload.serviceName="cloudresourcemanager.googleapis.com" AND ' +
					'protoPayload.methodName="SetIamPolicy" AND ' +
					'protoPayload.serviceData.policyDelta.bindingDeltas.action=("ADD" OR "REMOVE") AND ' +
					'protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner"'
			};

			const mockAlertPolicy = {
				conditions: [
					{
						conditionThreshold: {
							filter: "ownership-changes",
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

			const result = await checkProjectOwnershipMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe(
				"Valid metric filter and alert policy exist for project ownership changes"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when metric filter is missing", async () => {
			mockListLogMetrics.mockResolvedValueOnce([[]]);

			const result = await checkProjectOwnershipMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No valid log metric filter found for project ownership changes"
			);
		});

		it("should return FAIL when alert policy is missing", async () => {
			const mockMetric = {
				name: "ownership-changes",
				filter:
					'resource.type="project" AND ' +
					'protoPayload.serviceName="cloudresourcemanager.googleapis.com" AND ' +
					'protoPayload.methodName="SetIamPolicy" AND ' +
					'protoPayload.serviceData.policyDelta.bindingDeltas.action=("ADD" OR "REMOVE") AND ' +
					'protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[]]);

			const result = await checkProjectOwnershipMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No valid alert policy found for project ownership changes"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when listLogMetrics fails", async () => {
			mockListLogMetrics.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkProjectOwnershipMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking project ownership monitoring");
		});

		it("should return ERROR when listAlertPolicies fails", async () => {
			const mockMetric = {
				name: "ownership-changes",
				filter:
					'resource.type="project" AND ' +
					'protoPayload.serviceName="cloudresourcemanager.googleapis.com" AND ' +
					'protoPayload.methodName="SetIamPolicy" AND ' +
					'protoPayload.serviceData.policyDelta.bindingDeltas.action=("ADD" OR "REMOVE") AND ' +
					'protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkProjectOwnershipMonitoring.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking project ownership monitoring");
		});
	});
});
