// @ts-nocheck
import { InstancesClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkConfidentialComputing from "./gcp_confidential_computing.js";

describe("checkConfidentialComputing", () => {
	let mockInstancesClient: jest.Mocked<InstancesClient>;
	const DEFAULT_ZONE = "us-central1-a";

	beforeEach(() => {
		// Create a mock InstancesClient
		mockInstancesClient = {
			list: jest.fn().mockResolvedValue([[]])
		} as any;

		// Mock the InstancesClient constructor
		jest.spyOn(InstancesClient.prototype, "list").mockImplementation(mockInstancesClient.list);
	});

	afterEach(() => {
		jest.restoreAllMocks();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Confidential Computing is enabled", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: `projects/test-project/zones/${DEFAULT_ZONE}/instances/test-instance-1`,
				confidentialInstanceConfig: {
					enableConfidentialCompute: true
				}
			};

			mockInstancesClient.list.mockResolvedValue([[mockInstance]]);

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-instance-1");
		});

		it("should handle multiple instances with Confidential Computing", async () => {
			const mockInstances = [
				{
					name: "test-instance-1",
					selfLink: `projects/test-project/zones/${DEFAULT_ZONE}/instances/test-instance-1`,
					confidentialInstanceConfig: {
						enableConfidentialCompute: true
					}
				},
				{
					name: "test-instance-2",
					selfLink: `projects/test-project/zones/${DEFAULT_ZONE}/instances/test-instance-2`,
					confidentialInstanceConfig: {
						enableConfidentialCompute: true
					}
				}
			];

			mockInstancesClient.list.mockResolvedValue([mockInstances]);

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Confidential Computing is disabled", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: `projects/test-project/zones/${DEFAULT_ZONE}/instances/test-instance-1`,
				confidentialInstanceConfig: {
					enableConfidentialCompute: false
				}
			};

			mockInstancesClient.list.mockResolvedValue([[mockInstance]]);

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("does not have Confidential Computing enabled");
			expect(result.checks[0]?.message).toContain(DEFAULT_ZONE);
		});

		it("should return FAIL when Confidential Computing config is missing", async () => {
			const mockInstance = {
				name: "test-instance-1",
				selfLink: `projects/test-project/zones/${DEFAULT_ZONE}/instances/test-instance-1`
			};

			mockInstancesClient.list.mockResolvedValue([[mockInstance]]);

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no compute instances exist", async () => {
			mockInstancesClient.list.mockResolvedValue([[]]);

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe(`No compute instances found in zone ${DEFAULT_ZONE}`);
		});

		it("should handle compute instance without a name", async () => {
			const mockInstance = {
				selfLink: `projects/test-project/zones/${DEFAULT_ZONE}/instances/unnamed-instance`
			};

			mockInstancesClient.list.mockResolvedValue([[mockInstance]]);

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.resourceName).toBe("Unknown Instance");
		});

		it("should use provided zone instead of default", async () => {
			const customZone = "us-west1-b";
			mockInstancesClient.list.mockResolvedValue([[]]);

			const result = await checkConfidentialComputing.execute("test-project", customZone);
			expect(result.checks[0]?.message).toBe(`No compute instances found in zone ${customZone}`);
		});

		it("should return ERROR when project ID is not provided", async () => {
			const result = await checkConfidentialComputing.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockInstancesClient.list.mockRejectedValue(new Error("API Error"));

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking Confidential Computing: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockInstancesClient.list.mockRejectedValue("Unknown error");

			const result = await checkConfidentialComputing.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				"Error checking Confidential Computing: Unknown error"
			);
		});
	});
});
