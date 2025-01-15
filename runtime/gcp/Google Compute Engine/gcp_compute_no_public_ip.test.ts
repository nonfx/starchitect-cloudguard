// @ts-nocheck
import { describe, it, expect, beforeEach } from "vitest";
import { InstancesClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkComputeInstancePublicIPs from "./gcp_compute_no_public_ip.js";

describe("checkComputeInstancePublicIPs", () => {
	beforeEach(() => {
		// Reset the mock
		InstancesClient.prototype.list = async () => [[], null, {}];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when instance has no public IP", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				networkInterfaces: [
					{
						network: "default",
						networkIP: "10.0.0.2"
					}
				]
			};

			InstancesClient.prototype.list = async () => [[mockInstance], null, {}];

			const result = await checkComputeInstancePublicIPs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-instance-1");
		});

		it("should handle multiple instances without public IPs", async () => {
			const mockInstances = [
				{
					name: "test-instance-1",
					selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
					networkInterfaces: [
						{
							network: "default",
							networkIP: "10.0.0.2"
						}
					]
				},
				{
					name: "test-instance-2",
					selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-2",
					networkInterfaces: [
						{
							network: "default",
							networkIP: "10.0.0.3"
						}
					]
				}
			];

			InstancesClient.prototype.list = async () => [mockInstances, null, {}];

			const result = await checkComputeInstancePublicIPs.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when instance has public IP", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				networkInterfaces: [
					{
						network: "default",
						networkIP: "10.0.0.2",
						accessConfigs: [
							{
								natIP: "34.123.123.123"
							}
						]
					}
				]
			};

			InstancesClient.prototype.list = async () => [[mockInstance], null, {}];

			const result = await checkComputeInstancePublicIPs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("has a public IP address configured");
			expect(result.checks[0]?.message).toContain("us-central1-a"); // Check for zone in message
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			InstancesClient.prototype.list = async () => [[], null, {}];

			const result = await checkComputeInstancePublicIPs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No compute instances found in zone us-central1-a");
		});

		it("should handle instance without name", async () => {
			const mockInstance = {
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				networkInterfaces: [
					{
						network: "default",
						networkIP: "10.0.0.2"
					}
				]
			};

			InstancesClient.prototype.list = async () => [[mockInstance], null, {}];

			const result = await checkComputeInstancePublicIPs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Instance");
		});

		it("should handle instance without selfLink", async () => {
			const mockInstance = {
				name: "test-instance-1",
				networkInterfaces: [
					{
						network: "default",
						networkIP: "10.0.0.2"
					}
				]
			};

			InstancesClient.prototype.list = async () => [[mockInstance], null, {}];

			const result = await checkComputeInstancePublicIPs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceArn).toBeUndefined();
		});

		it("should use default zone when none provided", async () => {
			const mockInstance = {
				name: "test-instance-1",
				networkInterfaces: []
			};

			InstancesClient.prototype.list = async params => {
				expect(params.zone).toBe("us-central1-a"); // Verify default zone
				return [[mockInstance], null, {}];
			};

			await checkComputeInstancePublicIPs.execute("test-project");
		});

		it("should handle missing project ID", async () => {
			const result = await checkComputeInstancePublicIPs.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			InstancesClient.prototype.list = async () => {
				throw new Error("API Error");
			};

			const result = await checkComputeInstancePublicIPs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking compute instance public IPs: API Error"
			);
		});

		it("should handle non-Error exceptions", async () => {
			InstancesClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkComputeInstancePublicIPs.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking compute instance public IPs: Unknown error"
			);
		});
	});
});
