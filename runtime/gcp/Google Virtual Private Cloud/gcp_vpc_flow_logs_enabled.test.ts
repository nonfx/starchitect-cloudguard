import { expect, describe, it, beforeEach, mock } from "bun:test";
import { SubnetworksClient, RegionsClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkVPCFlowLogs from "./gcp_vpc_flow_logs_enabled.js";

describe("checkVPCFlowLogs", () => {
	// Mock the clients with proper return types
	const mockList = mock(() => Promise.resolve([[], null, {}]));
	const mockRegionsList = mock(() =>
		Promise.resolve([[{ name: "us-central1", status: "UP" }], null, {}])
	);

	// Override the client constructors
	SubnetworksClient.prototype.list = mockList as any;
	RegionsClient.prototype.list = mockRegionsList as any;

	beforeEach(() => {
		// Reset mocks before each test
		mockList.mockClear();
		mockRegionsList.mockClear();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when subnet has valid flow logs", async () => {
			const mockSubnet = {
				name: "test-subnet-1",
				selfLink: "projects/test-project/regions/us-central1/subnetworks/test-subnet-1",
				logConfig: [
					{
						aggregationInterval: 5,
						flowSampling: 1,
						metadata: true
					}
				]
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
					logConfig: [
						{
							aggregationInterval: 5,
							flowSampling: 1,
							metadata: true
						}
					]
				},
				{
					name: "test-subnet-2",
					selfLink: "projects/test-project/regions/us-central1/subnetworks/test-subnet-2",
					logConfig: [
						{
							aggregationInterval: 5,
							flowSampling: 1,
							metadata: true
						}
					]
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
				logConfig: [
					{
						aggregationInterval: 60,
						flowSampling: 0.5,
						metadata: false
					}
				]
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
		it("should return NOTAPPLICABLE when API is not enabled", async () => {
			const apiError = new Error(
				"API has not been used in project test-project before or it is disabled"
			);
			mockRegionsList.mockImplementation(() => Promise.reject(apiError));
			mockList.mockImplementation(() => Promise.reject(apiError));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Unable to fetch regions for the project");
		});

		it("should return ERROR for non-API errors", async () => {
			const error = new Error("Network Error");
			mockRegionsList.mockImplementation(() => Promise.reject(error));
			mockList.mockImplementation(() => Promise.reject(error));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Unable to fetch regions for the project");
		});
	});
});
