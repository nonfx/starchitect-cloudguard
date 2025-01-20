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
				name: "projects/test-project/metrics/vpc-network-changes",
				filter:
					'resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")',
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
					name: "projects/test-project/metricDescriptors/logging.googleapis.com/user/vpc-network-changes",
					metricKind: "DELTA",
					valueType: "INT64",
					unit: "1",
					description: "",
					type: "logging.googleapis.com/user/vpc-network-changes"
				}
			};

			const mockAlertPolicy = {
				displayName: "VPC Network Changes Alert",
				conditions: [
					{
						displayName: "VPC Network Changes",
						conditionThreshold: {
							filter: 'metric.type="logging.googleapis.com/user/vpc-network-changes"',
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
				name: "projects/test-project/metrics/vpc-network-changes",
				filter: 'resource.type="gce_instance"',
				labelExtractors: {},
				valueExtractor: "",
				bucketOptions: null,
				version: "V2",
				metricDescriptor: {
					name: "projects/test-project/metricDescriptors/logging.googleapis.com/user/vpc-network-changes",
					metricKind: "DELTA",
					valueType: "INT64",
					unit: "1",
					type: "logging.googleapis.com/user/vpc-network-changes"
				}
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);

			const result = await checkVpcNetworkChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No metric filter found for VPC network changes");
		});

		it("should return FAIL when alert policy is missing", async () => {
			const mockMetric = {
				name: "projects/test-project/metrics/vpc-network-changes",
				filter:
					'resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")',
				labelExtractors: {},
				valueExtractor: "",
				bucketOptions: null,
				version: "V2",
				metricDescriptor: {
					name: "projects/test-project/metricDescriptors/logging.googleapis.com/user/vpc-network-changes",
					metricKind: "DELTA",
					valueType: "INT64",
					unit: "1",
					type: "logging.googleapis.com/user/vpc-network-changes"
				}
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockResolvedValueOnce([[]]);

			const result = await checkVpcNetworkChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No valid alert policy found for VPC network changes");
		});

		it("should return FAIL when alert policy has incorrect configuration", async () => {
			const mockMetric = {
				name: "projects/test-project/metrics/vpc-network-changes",
				filter:
					'resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")',
				labelExtractors: {},
				valueExtractor: "",
				bucketOptions: null,
				version: "V2",
				metricDescriptor: {
					name: "projects/test-project/metricDescriptors/logging.googleapis.com/user/vpc-network-changes",
					metricKind: "DELTA",
					valueType: "INT64",
					unit: "1",
					type: "logging.googleapis.com/user/vpc-network-changes"
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

		it("should return ERROR when listAlertPolicies fails", async () => {
			const mockMetric = {
				name: "projects/test-project/metrics/vpc-network-changes",
				filter:
					'resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")',
				labelExtractors: {},
				valueExtractor: "",
				bucketOptions: null,
				version: "V2",
				metricDescriptor: {
					name: "projects/test-project/metricDescriptors/logging.googleapis.com/user/vpc-network-changes",
					metricKind: "DELTA",
					valueType: "INT64",
					unit: "1",
					type: "logging.googleapis.com/user/vpc-network-changes"
				}
			};

			mockListLogMetrics.mockResolvedValueOnce([[mockMetric]]);
			mockListAlertPolicies.mockRejectedValueOnce(new Error("API Error"));

			const result = await checkVpcNetworkChanges.execute("test-project");

			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking VPC network changes monitoring");
		});
	});
});
