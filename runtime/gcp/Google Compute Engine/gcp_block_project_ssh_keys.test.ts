import { expect, describe, it, beforeEach, mock } from "bun:test";
import { InstancesClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkBlockProjectSSHKeys from "./gcp_block_project_ssh_keys.js";

describe("checkBlockProjectSSHKeys", () => {
	// Mock the client
	const mockList = mock(() => Promise.resolve([[], null, {}]));

	beforeEach(() => {
		// Set up client mock before each test
		InstancesClient.prototype.list = mockList as any;
		// Reset mock call history
		mockList.mockClear();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when instance blocks project SSH keys", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				metadata: {
					items: [{ key: "block-project-ssh-keys", value: "true" }]
				}
			};

			mockList.mockImplementation(() => Promise.resolve([[mockInstance], null, {}]));

			const result = await checkBlockProjectSSHKeys.execute("test-project", "us-central1-a");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});

		it("should handle multiple compliant instances", async () => {
			const mockInstances = [
				{
					name: "test-instance-1",
					selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
					metadata: {
						items: [{ key: "block-project-ssh-keys", value: "true" }]
					}
				},
				{
					name: "test-instance-2",
					selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-2",
					metadata: {
						items: [{ key: "block-project-ssh-keys", value: "true" }]
					}
				}
			];

			mockList.mockImplementation(() => Promise.resolve([mockInstances, null, {}]));

			const result = await checkBlockProjectSSHKeys.execute("test-project", "us-central1-a");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when instance does not block project SSH keys", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				metadata: {
					items: []
				}
			};

			mockList.mockImplementation(() => Promise.resolve([[mockInstance], null, {}]));

			const result = await checkBlockProjectSSHKeys.execute("test-project", "us-central1-a");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("does not block project-wide SSH keys");
		});

		it("should return FAIL when metadata is missing", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1"
			};

			mockList.mockImplementation(() => Promise.resolve([[mockInstance], null, {}]));

			const result = await checkBlockProjectSSHKeys.execute("test-project", "us-central1-a");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			mockList.mockImplementation(() => Promise.resolve([[], null, {}]));

			const result = await checkBlockProjectSSHKeys.execute("test-project", "us-central1-a");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No compute instances found in zone us-central1-a");
		});

		it("should handle instance without name", async () => {
			const mockInstance = {
				selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
				metadata: {
					items: [{ key: "block-project-ssh-keys", value: "true" }]
				}
			};

			mockList.mockImplementation(() => Promise.resolve([[mockInstance], null, {}]));

			const result = await checkBlockProjectSSHKeys.execute("test-project", "us-central1-a");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Instance");
		});

		it("should use default zone when none provided", async () => {
			mockList.mockImplementation(() => Promise.resolve([[], null, {}]));

			const result = await checkBlockProjectSSHKeys.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.message).toContain("us-central1-a");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when project ID is not provided", async () => {
			const result = await checkBlockProjectSSHKeys.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});

		it("should return ERROR when API call fails", async () => {
			const apiError = new Error("API Error");
			mockList.mockImplementation(() => Promise.reject(apiError));

			const result = await checkBlockProjectSSHKeys.execute("test-project", "us-central1-a");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking blocked project SSH keys: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockList.mockImplementation(() => Promise.reject("Unknown error"));

			const result = await checkBlockProjectSSHKeys.execute("test-project", "us-central1-a");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking blocked project SSH keys: Unknown error"
			);
		});
	});
});
