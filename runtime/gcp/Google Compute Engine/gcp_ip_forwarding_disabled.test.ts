// @ts-nocheck
import { InstancesClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkConfidentialComputing from "./gcp_ip_forwarding_disabled.js";

describe("checkConfidentialComputing", () => {
	beforeEach(() => {
		// Reset the mock
		InstancesClient.prototype.list = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Confidential Computing is enabled", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				confidentialInstanceConfig: {
					enableConfidentialCompute: true
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-instance-1");
		});

		it("should handle multiple instances with Confidential Computing enabled", async () => {
			const mockInstances = [
				{
					name: "test-instance-1",
					confidentialInstanceConfig: {
						enableConfidentialCompute: true
					}
				},
				{
					name: "test-instance-2",
					confidentialInstanceConfig: {
						enableConfidentialCompute: true
					}
				}
			];

			InstancesClient.prototype.list = async () => [mockInstances];

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Confidential Computing is disabled", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				confidentialInstanceConfig: {
					enableConfidentialCompute: false
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("does not have Confidential Computing enabled");
		});

		it("should return FAIL when confidentialInstanceConfig is missing", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1"
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			InstancesClient.prototype.list = async () => [[]];

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No compute instances found in zone us-central1-a");
		});

		it("should handle instance without name", async () => {
			const mockInstance = {
				confidentialInstanceConfig: {
					enableConfidentialCompute: true
				}
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Instance");
		});

		it("should handle missing project ID", async () => {
			const result = await checkConfidentialComputing.execute("");
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

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking Confidential Computing: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			InstancesClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking Confidential Computing: Unknown error"
			);
		});
	});
});
