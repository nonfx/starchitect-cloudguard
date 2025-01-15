// @ts-nocheck
import { InstancesClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkShieldedVMEnabled from "./gcp_shielded_vm_enabled.js";

describe("checkShieldedVMEnabled", () => {
	beforeEach(() => {
		// Reset the mock
		InstancesClient.prototype.list = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Shielded VM is properly configured", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				shieldedInstanceConfig: {
					enableVtpm: true,
					enableIntegrityMonitoring: true
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkShieldedVMEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-instance-1");
		});

		it("should handle multiple compliant instances", async () => {
			const mockInstances = [
				{
					name: "instance-1",
					shieldedInstanceConfig: {
						enableVtpm: true,
						enableIntegrityMonitoring: true
					}
				},
				{
					name: "instance-2",
					shieldedInstanceConfig: {
						enableVtpm: true,
						enableIntegrityMonitoring: true
					}
				}
			];

			InstancesClient.prototype.list = async () => [mockInstances];

			const result = await checkShieldedVMEnabled.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Shielded VM is not enabled", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				shieldedInstanceConfig: {
					enableVtpm: false,
					enableIntegrityMonitoring: false
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkShieldedVMEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("does not have Shielded VM properly configured");
		});

		it("should return FAIL when only vTPM is enabled", async () => {
			const mockInstance = {
				name: "test-instance-1",
				shieldedInstanceConfig: {
					enableVtpm: true,
					enableIntegrityMonitoring: false
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkShieldedVMEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});

		it("should return FAIL when only Integrity Monitoring is enabled", async () => {
			const mockInstance = {
				name: "test-instance-1",
				shieldedInstanceConfig: {
					enableVtpm: false,
					enableIntegrityMonitoring: true
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkShieldedVMEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			InstancesClient.prototype.list = async () => [[]];

			const result = await checkShieldedVMEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No compute instances found in zone us-central1-a");
		});

		it("should handle missing shieldedInstanceConfig", async () => {
			const mockInstance = {
				name: "test-instance-1"
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkShieldedVMEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle instance without name", async () => {
			const mockInstance = {
				shieldedInstanceConfig: {
					enableVtpm: true,
					enableIntegrityMonitoring: true
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkShieldedVMEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Instance");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			InstancesClient.prototype.list = async () => {
				throw new Error("API Error");
			};

			const result = await checkShieldedVMEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking Shielded VM configuration: API Error");
		});

		it("should handle missing project ID", async () => {
			const result = await checkShieldedVMEnabled.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});

		it("should handle non-Error exceptions", async () => {
			InstancesClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkShieldedVMEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking Shielded VM configuration: Unknown error"
			);
		});
	});
});
