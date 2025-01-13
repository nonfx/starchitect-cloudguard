// @ts-nocheck
import { NetworksClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkDefaultNetwork from "./gcp_no_default_network.js";

describe("checkDefaultNetwork", () => {
	beforeEach(() => {
		// Reset the mock
		NetworksClient.prototype.list = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when no default network exists", async () => {
			const mockNetworks = [
				{
					name: "custom-network-1",
					selfLink: "projects/test-project/global/networks/custom-network-1"
				},
				{
					name: "custom-network-2",
					selfLink: "projects/test-project/global/networks/custom-network-2"
				}
			];

			NetworksClient.prototype.list = async () => [mockNetworks];

			const result = await checkDefaultNetwork.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.message).toBe("No default network found in the project");
		});

		it("should handle project with single custom network", async () => {
			const mockNetworks = [
				{
					name: "custom-network",
					selfLink: "projects/test-project/global/networks/custom-network"
				}
			];

			NetworksClient.prototype.list = async () => [mockNetworks];

			const result = await checkDefaultNetwork.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when default network exists", async () => {
			const mockNetworks = [
				{
					name: "default",
					selfLink: "projects/test-project/global/networks/default"
				}
			];

			NetworksClient.prototype.list = async () => [mockNetworks];

			const result = await checkDefaultNetwork.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Default network detected in project");
			expect(result.checks[0]?.resourceName).toBe("default");
		});

		it("should detect default network among multiple networks", async () => {
			const mockNetworks = [
				{
					name: "custom-network",
					selfLink: "projects/test-project/global/networks/custom-network"
				},
				{
					name: "default",
					selfLink: "projects/test-project/global/networks/default"
				}
			];

			NetworksClient.prototype.list = async () => [mockNetworks];

			const result = await checkDefaultNetwork.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no networks exist", async () => {
			NetworksClient.prototype.list = async () => [[]];

			const result = await checkDefaultNetwork.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No networks found in the project");
		});

		it("should handle network without selfLink", async () => {
			const mockNetworks = [
				{
					name: "default"
				}
			];

			NetworksClient.prototype.list = async () => [mockNetworks];

			const result = await checkDefaultNetwork.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceArn).toBeUndefined();
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			NetworksClient.prototype.list = async () => {
				throw new Error("API Error");
			};

			const result = await checkDefaultNetwork.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking default network: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			NetworksClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkDefaultNetwork.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking default network: Unknown error");
		});

		it("should handle undefined project ID", async () => {
			const result = await checkDefaultNetwork.execute(undefined);
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
		});
	});
});
