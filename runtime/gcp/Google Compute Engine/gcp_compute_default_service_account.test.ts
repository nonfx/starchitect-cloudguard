// @ts-nocheck
import { InstancesClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkDefaultServiceAccount from "./gcp_compute_default_service_account.js";

describe("checkDefaultServiceAccount", () => {
	beforeEach(() => {
		// Reset the mock
		InstancesClient.prototype.list = async () => [[]];
	});

	describe("Compliant Resources", () => {
		it("should return PASS when instance uses custom service account", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				serviceAccounts: [
					{
						email: "custom-sa@my-project.iam.gserviceaccount.com"
					}
				]
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkDefaultServiceAccount.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-instance-1");
		});

		it("should handle multiple instances with custom service accounts", async () => {
			const mockInstances = [
				{
					name: "test-instance-1",
					serviceAccounts: [
						{
							email: "custom-sa-1@my-project.iam.gserviceaccount.com"
						}
					]
				},
				{
					name: "test-instance-2",
					serviceAccounts: [
						{
							email: "custom-sa-2@my-project.iam.gserviceaccount.com"
						}
					]
				}
			];

			InstancesClient.prototype.list = async () => [mockInstances];

			const result = await checkDefaultServiceAccount.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when instance uses default service account", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				serviceAccounts: [
					{
						email: "123456-compute@developer.gserviceaccount.com"
					}
				]
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkDefaultServiceAccount.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("uses default compute service account");
		});

		it("should detect multiple instances using default service account", async () => {
			const mockInstances = [
				{
					name: "test-instance-1",
					serviceAccounts: [
						{
							email: "123456-compute@developer.gserviceaccount.com"
						}
					]
				},
				{
					name: "test-instance-2",
					serviceAccounts: [
						{
							email: "789012-compute@developer.gserviceaccount.com"
						}
					]
				}
			];

			InstancesClient.prototype.list = async () => [mockInstances];

			const result = await checkDefaultServiceAccount.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.FAIL)).toBe(true);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			InstancesClient.prototype.list = async () => [[]];

			const result = await checkDefaultServiceAccount.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No compute instances found in zone us-central1-a");
		});

		it("should handle instance without service accounts", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1"
			};

			InstancesClient.prototype.list = async () => [[mockInstance]];

			const result = await checkDefaultServiceAccount.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});

		it("should handle missing project ID", async () => {
			const result = await checkDefaultServiceAccount.execute("");
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

			const result = await checkDefaultServiceAccount.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking default service account usage: API Error"
			);
		});

		it("should handle non-Error exceptions", async () => {
			InstancesClient.prototype.list = async () => {
				throw "Unknown error";
			};

			const result = await checkDefaultServiceAccount.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking default service account usage: Unknown error"
			);
		});
	});
});
