// @ts-nocheck
import { SubnetworksClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkVPCFlowLogs from "./check-vpc-flow-logs.ts";

describe("checkVPCFlowLogs", () => {
	let mockSubnetworksClient: jest.Mocked<SubnetworksClient>;

	beforeEach(() => {
		// Create a mock SubnetworksClient
		mockSubnetworksClient = {
			list: jest.fn().mockResolvedValue([[]])
		} as any;

		// Mock the SubnetworksClient constructor
		jest.spyOn(SubnetworksClient.prototype, "list").mockImplementation(mockSubnetworksClient.list);
	});

	afterEach(() => {
		jest.restoreAllMocks();
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

			mockSubnetworksClient.list.mockResolvedValue([[mockSubnet]]);

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

			mockSubnetworksClient.list.mockResolvedValue([mockSubnets]);

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when subnet has no flow logs", async () => {
			const mockSubnet = {
				name: "test-subnet-1",
				selfLink: "projects/test-project/regions/us-central1/subnetworks/test-subnet-1",
				logConfig: []
			};

			mockSubnetworksClient.list.mockResolvedValue([[mockSubnet]]);

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

			mockSubnetworksClient.list.mockResolvedValue([[mockSubnet]]);

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no subnets exist", async () => {
			mockSubnetworksClient.list.mockResolvedValue([[]]);

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No VPC subnets found in the project");
		});

		it("should return NOTAPPLICABLE for managed proxy subnets", async () => {
			const mockSubnet = {
				name: "test-subnet-1",
				selfLink: "projects/test-project/regions/us-central1/subnetworks/test-subnet-1",
				purpose: "REGIONAL_MANAGED_PROXY"
			};

			mockSubnetworksClient.list.mockResolvedValue([[mockSubnet]]);

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("Subnet is not eligible for flow logs configuration");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockSubnetworksClient.list.mockRejectedValue(new Error("API Error"));

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking VPC flow logs: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockSubnetworksClient.list.mockRejectedValue("Unknown error");

			const result = await checkVPCFlowLogs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking VPC flow logs: Unknown error");
		});
	});
});
