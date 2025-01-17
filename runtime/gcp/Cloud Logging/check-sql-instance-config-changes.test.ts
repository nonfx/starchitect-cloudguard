// @ts-nocheck
import { AlertPolicyServiceClient, protos } from "@google-cloud/monitoring";
import { v2 } from "@google-cloud/logging";
import { ComplianceStatus } from "../../types.js";
import checkSqlInstanceConfigChanges from "./check-sql-instance-config-changes.js";

describe("checkSqlInstanceConfigChanges", () => {
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
		it("should return PASS when metric filter and alert policy are properly configured", async () => {
			const mockMetric = {
				name: "sql-config-metric",
				filter:
					'resource.type="cloudsql_database" AND protoPayload.methodName="cloudsql.instances.update"'
			};

			const mockAlertPolicy = {
				conditions: [
					{
						displayName: "SQL Instance Configuration Changes",
						conditionThreshold: {
							filter: "sql-config-metric",
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

			const result = await checkSqlInstanceConfigChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe(
				"Metric filter and alert policy are properly configured"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when metric filter is missing", async () => {
			mockListLogMetrics.mockResolvedValueOnce([[]]);

			const result = await checkSqlInstanceConfigChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No metric filter found for SQL instance configuration changes"
			);
		});

		it("should return FAIL when alert policy is missing", async () => {
			const mockMetric = {
				name: "sql-config-metric",
				filter:
					'resource.type="cloudsql_database" AND protoPayload.methodName="cloudsql.instances.update"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[]]);

			const result = await checkSqlInstanceConfigChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No alert policy found for SQL instance configuration changes"
			);
		});

		it("should return FAIL when alert policy has incorrect configuration", async () => {
			const mockMetric = {
				name: "sql-config-metric",
				filter:
					'resource.type="cloudsql_database" AND protoPayload.methodName="cloudsql.instances.update"'
			};

			const mockAlertPolicy = {
				conditions: [
					{
						displayName: "Wrong Display Name",
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

			const result = await checkSqlInstanceConfigChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No alert policy found for SQL instance configuration changes"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when listLogMetrics fails", async () => {
			mockListLogMetrics.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkSqlInstanceConfigChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking SQL config change monitoring");
		});

		it("should return ERROR when listAlertPolicies fails", async () => {
			const mockMetric = {
				name: "sql-config-metric",
				filter:
					'resource.type="cloudsql_database" AND protoPayload.methodName="cloudsql.instances.update"'
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkSqlInstanceConfigChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking SQL config change monitoring");
		});
	});
});
