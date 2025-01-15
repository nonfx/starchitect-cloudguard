// @ts-nocheck
import { checkIpForwardingDisabled } from "./gcp_ip_forwarding_disabled.js";
import { ComplianceStatus } from "../../types.js";
import { InstancesClient } from "@google-cloud/compute";

describe("checkIpForwardingDisabled", () => {
	describe("Compliant Resources", () => {
		it("should return PASS when IP forwarding is disabled", async () => {
			const mockInstance = {
				name: "test-instance",
				canIpForward: false
			};

			InstancesClient.prototype.list = async () => [[mockInstance], null, {}];

			const result = await checkIpForwardingDisabled("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});

		it("should handle multiple instances with IP forwarding disabled", async () => {
			const mockInstances = [
				{ name: "instance-1", canIpForward: false },
				{ name: "instance-2", canIpForward: false }
			];

			InstancesClient.prototype.list = async () => [mockInstances, null, {}];

			const result = await checkIpForwardingDisabled("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when IP forwarding is enabled", async () => {
			const mockInstance = {
				name: "test-instance",
				canIpForward: true
			};

			InstancesClient.prototype.list = async () => [[mockInstance], null, {}];

			const result = await checkIpForwardingDisabled("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"Instance test-instance has IP forwarding enabled. Disable IP forwarding unless required for network routing."
			);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			InstancesClient.prototype.list = async () => [[], null, {}];

			const result = await checkIpForwardingDisabled("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No compute instances found in zone us-central1-a");
		});

		it("should handle instance without name", async () => {
			const mockInstance = {
				canIpForward: false
			};

			InstancesClient.prototype.list = async () => [[mockInstance], null, {}];

			const result = await checkIpForwardingDisabled("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Instance");
		});

		it("should handle missing project ID", async () => {
			const result = await checkIpForwardingDisabled("");
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

			const result = await checkIpForwardingDisabled("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking IP forwarding: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			InstancesClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkIpForwardingDisabled("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking IP forwarding: Unknown error");
		});
	});
});
