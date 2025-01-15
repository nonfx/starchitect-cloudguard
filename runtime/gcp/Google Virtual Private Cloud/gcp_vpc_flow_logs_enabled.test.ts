import { expect, describe, it, beforeEach, mock } from "bun:test";
import { SubnetworksClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkVPCFlowLogs from "./gcp_vpc_flow_logs_enabled.js";

describe("checkVPCFlowLogs", () => {
	// Mock the client
	const mockList = mock(() => Promise.resolve([[], null, {}]));

	beforeEach(() => {
		// Set up client mock before each test
		SubnetworksClient.prototype.list = mockList as any;
		// Reset mock call history
		mockList.mockClear();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when subnet has valid flow logs", async () => {
			const mockSubnet = {
				name: "test-subnet-1",
				selfLink: "projects/test-project/regions/us-central1/subnetworks/test-subnet-1",
				logConfig: {
					aggregationInterval: "INTERVAL_5_SEC",
					flowSampling: 1,
					metadata: "INCLUDE_ALL_METADATA"
				}
			};

			mockList.mockImplementation(() => Promise.resolve([[mockSubnet], null, {}]));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-subnet-1");
		});

		it("should handle multiple subnets with valid flow logs", async () => {
			const mockSubnets = [
				{
					name: "test-subnet-1",
					selfLink: "projects/test-project/regions/us-central1/subnetworks/test-subnet-1",
					logConfig: {
						aggregationInterval: "INTERVAL_5_SEC",
						flowSampling: 1,
						metadata: "INCLUDE_ALL_METADATA"
					}
				},
				{
					name: "test-subnet-2",
					selfLink: "projects/test-project/regions/us-central1/subnetworks/test-subnet-2",
					logConfig: {
						aggregationInterval: "INTERVAL_5_SEC",
						flowSampling: 1,
						metadata: "INCLUDE_ALL_METADATA"
					}
				}
			];

			mockList.mockImplementation(() => Promise.resolve([mockSubnets, null, {}]));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when subnet has no flow logs", async () => {
			const mockSubnet = {
				name: "test-subnet-1",
				selfLink: "projects/test-project/regions/us-central1/subnetworks/test-subnet-1"
			};

			mockList.mockImplementation(() => Promise.resolve([[mockSubnet], null, {}]));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("VPC Flow Logs must be enabled");
		});

		it("should return FAIL when flow logs do not meet all criteria", async () => {
			const mockSubnet = {
				name: "test-subnet-1",
				selfLink: "projects/test-project/regions/us-central1/subnetworks/test-subnet-1",
				logConfig: {
					aggregationInterval: "INTERVAL_300_SEC",
					flowSampling: 0.5,
					metadata: "EXCLUDE_ALL_METADATA"
				}
			};

			mockList.mockImplementation(() => Promise.resolve([[mockSubnet], null, {}]));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no subnets exist", async () => {
			mockList.mockImplementation(() => Promise.resolve([[], null, {}]));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No VPC subnets found in any region of the project");
		});

		it("should return NOTAPPLICABLE for managed proxy subnets", async () => {
			const mockSubnet = {
				name: "test-subnet-1",
				selfLink: "projects/test-project/regions/us-central1/subnetworks/test-subnet-1",
				purpose: "REGIONAL_MANAGED_PROXY"
			};

			mockList.mockImplementation(() => Promise.resolve([[mockSubnet], null, {}]));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("Subnet is not eligible for flow logs configuration");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API is not enabled", async () => {
			const apiError = new Error(
				"API has not been used in project test-project before or it is disabled"
			);
			mockList.mockImplementation(() => Promise.reject(apiError));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking VPC flow logs");
		});

		it("should return ERROR for non-API errors", async () => {
			const error = new Error("Network Error");
			mockList.mockImplementation(() => Promise.reject(error));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking VPC flow logs");
		});
	});
});
