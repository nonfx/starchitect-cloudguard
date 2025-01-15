// @ts-nocheck
import { InstancesClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkIpForwardingDisabled from "./gcp-ip-forwarding-disabled.js";

describe("checkIpForwardingDisabled", () => {
	beforeEach(() => {
		// Reset the mock
		InstancesClient.prototype.list = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when IP forwarding is disabled", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				canIpForward: false
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkIpForwardingDisabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-instance-1");
		});

		it("should handle multiple compliant instances", async () => {
			const mockInstances = [
				{
					name: "test-instance-1",
					selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
					canIpForward: false
				},
				{
					name: "test-instance-2",
					selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-2",
					canIpForward: false
				}
			];

			InstancesClient.prototype.list = async () => [mockInstances];

			const result = await checkIpForwardingDisabled.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when IP forwarding is enabled", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				canIpForward: true
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkIpForwardingDisabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("IP forwarding is enabled");
		});

		it("should handle mixed compliance states", async () => {
			const mockInstances = [
				{
					name: "test-instance-1",
					canIpForward: true
				},
				{
					name: "test-instance-2",
					canIpForward: false
				}
			];

			InstancesClient.prototype.list = async () => [mockInstances];

			const result = await checkIpForwardingDisabled.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			InstancesClient.prototype.list = async () => [[]];

			const result = await checkIpForwardingDisabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No compute instances found in zone us-central1-a");
		});

		it("should handle instance without name", async () => {
			const mockInstance = {
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				canIpForward: false
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkIpForwardingDisabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Instance");
		});

		it("should handle missing project ID", async () => {
			const result = await checkIpForwardingDisabled.execute("");
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

			const result = await checkIpForwardingDisabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking IP forwarding: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			InstancesClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkIpForwardingDisabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking IP forwarding: Unknown error");
		});
	});
});
