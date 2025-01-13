// @ts-nocheck
import { InstancesClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkVMSerialPorts from "./gcp_vm_serial_ports_disabled.js";

describe("checkVMSerialPorts", () => {
	beforeEach(() => {
		// Reset the mock
		InstancesClient.prototype.list = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when serial ports are disabled", async () => {
			const mockInstance = {
				name: "test-vm-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-vm-1",
				metadata: {
					items: [
						{
							key: "serial-port-enable",
							value: "false"
						}
					]
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkVMSerialPorts.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-vm-1");
		});

		it("should return PASS when metadata is not present", async () => {
			const mockInstance = {
				name: "test-vm-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-vm-1"
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkVMSerialPorts.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when serial ports are enabled", async () => {
			const mockInstance = {
				name: "test-vm-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-vm-1",
				metadata: {
					items: [
						{
							key: "serial-port-enable",
							value: "TRUE"
						}
					]
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkVMSerialPorts.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("has serial port access enabled");
		});

		it("should handle case-insensitive TRUE value", async () => {
			const mockInstance = {
				name: "test-vm-1",
				metadata: {
					items: [
						{
							key: "serial-port-enable",
							value: "true"
						}
					]
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkVMSerialPorts.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			InstancesClient.prototype.list = async () => [[]];

			const result = await checkVMSerialPorts.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No compute instances found in zone us-central1-a");
		});

		it("should handle instance without name", async () => {
			const mockInstance = {
				metadata: {
					items: [
						{
							key: "serial-port-enable",
							value: "true"
						}
					]
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkVMSerialPorts.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Instance");
		});

		it("should handle missing project ID", async () => {
			const result = await checkVMSerialPorts.execute("");
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

			const result = await checkVMSerialPorts.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking VM serial ports: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			InstancesClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkVMSerialPorts.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking VM serial ports: Unknown error");
		});
	});
});
