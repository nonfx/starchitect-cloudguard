// @ts-nocheck
import { ProjectsClient, InstancesClient } from "@google-cloud/compute";
import { ComplianceStatus } from "../../types.js";
import checkOsLoginEnabled from "./gcp_oslogin_enabled.js";

describe("checkOsLoginEnabled", () => {
	const DEFAULT_ZONE = "us-central1-a";
	let mockProjectsClient;
	let mockInstancesClient;

	beforeEach(() => {
		// Create mock clients
		mockProjectsClient = {
			get: jest.fn().mockResolvedValue([[]])
		};

		mockInstancesClient = {
			list: jest.fn().mockResolvedValue([[]])
		};

		// Mock the clients' constructors
		jest.spyOn(ProjectsClient.prototype, "get").mockImplementation(mockProjectsClient.get);
		jest.spyOn(InstancesClient.prototype, "list").mockImplementation(mockInstancesClient.list);
	});

	afterEach(() => {
		jest.restoreAllMocks();
	});

	describe("Project Level Compliance", () => {
		it("should return PASS when OS login is enabled at project level", async () => {
			const mockProject = {
				commonInstanceMetadata: {
					items: [
						{
							key: "enable-oslogin",
							value: "true"
						}
					],
					selfLink: "projects/test-project/global/metadata"
				}
			};

			mockProjectsClient.get.mockResolvedValue([mockProject]);

			const result = await checkOsLoginEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("Project test-project Metadata");
		});

		it("should check instances when OS login is not enabled at project level", async () => {
			const mockProject = {
				commonInstanceMetadata: {
					items: [
						{
							key: "enable-oslogin",
							value: "false"
						}
					],
					selfLink: "projects/test-project/global/metadata"
				}
			};

			const mockInstances = [
				{
					name: "test-instance-1",
					selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
					metadata: {
						items: [
							{
								key: "enable-oslogin",
								value: "true"
							}
						]
					}
				}
			];

			mockProjectsClient.get.mockResolvedValue([mockProject]);
			mockInstancesClient.list.mockResolvedValue([mockInstances]);

			const result = await checkOsLoginEnabled.execute("test-project");
			expect(result.checks).toHaveLength(2); // Project check + Instance check
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL); // Project level
			expect(result.checks[1]?.status).toBe(ComplianceStatus.PASS); // Instance level
		});
	});

	describe("Instance Level Compliance", () => {
		it("should check individual instances when project setting is not enabled", async () => {
			const mockProject = {
				commonInstanceMetadata: {
					items: []
				}
			};

			const mockInstances = [
				{
					name: "test-instance-1",
					selfLink: "projects/test-project/zones/us-central1-a/instances/test-instance-1",
					metadata: {
						items: [
							{
								key: "enable-oslogin",
								value: "true"
							}
						]
					}
				}
			];

			mockProjectsClient.get.mockResolvedValue([mockProject]);
			mockInstancesClient.list.mockResolvedValue([mockInstances]);

			const result = await checkOsLoginEnabled.execute("test-project");
			expect(result.checks.length).toBeGreaterThan(1);
			expect(result.checks.some(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});

		it("should handle multiple instances with different configurations", async () => {
			const mockProject = {
				commonInstanceMetadata: {
					items: []
				}
			};

			const mockInstances = [
				{
					name: "instance-enabled",
					metadata: {
						items: [{ key: "enable-oslogin", value: "true" }]
					}
				},
				{
					name: "instance-disabled",
					metadata: {
						items: [{ key: "enable-oslogin", value: "false" }]
					}
				}
			];

			mockProjectsClient.get.mockResolvedValue([mockProject]);
			mockInstancesClient.list.mockResolvedValue([mockInstances]);

			const result = await checkOsLoginEnabled.execute("test-project");
			expect(result.checks.length).toBeGreaterThan(2);
			expect(result.checks.filter(check => check.status === ComplianceStatus.PASS).length).toBe(1);
			expect(
				result.checks.filter(check => check.status === ComplianceStatus.FAIL).length
			).toBeGreaterThan(0);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			const mockProject = {
				commonInstanceMetadata: {
					items: [{ key: "enable-oslogin", value: "false" }]
				}
			};

			mockProjectsClient.get.mockResolvedValue([mockProject]);
			mockInstancesClient.list.mockResolvedValue([[]]);

			const result = await checkOsLoginEnabled.execute("test-project");
			expect(result.checks).toHaveLength(2); // Project check + NOTAPPLICABLE
			expect(result.checks[1]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[1]?.message).toBe(`No compute instances found in zone ${DEFAULT_ZONE}`);
		});

		it("should handle missing project ID", async () => {
			const result = await checkOsLoginEnabled.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});

		it("should use specified zone instead of default", async () => {
			const customZone = "us-west1-b";
			mockInstancesClient.list.mockImplementation(params => {
				expect(params.zone).toBe(customZone);
				return [[]];
			});

			await checkOsLoginEnabled.execute("test-project", customZone);
			expect(mockInstancesClient.list).toHaveBeenCalledWith(
				expect.objectContaining({ zone: customZone })
			);
		});
	});

	describe("Error Handling", () => {
		it("should handle API errors for project metadata", async () => {
			mockProjectsClient.get.mockRejectedValue(new Error("API Error"));

			const result = await checkOsLoginEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("API Error");
		});

		it("should handle API errors for instance listing", async () => {
			mockProjectsClient.get.mockResolvedValue([{ commonInstanceMetadata: { items: [] } }]);
			mockInstancesClient.list.mockRejectedValue(new Error("Instance API Error"));

			const result = await checkOsLoginEnabled.execute("test-project");
			expect(result.checks.some(check => check.message?.includes("Instance API Error"))).toBe(true);
		});

		it("should handle non-Error exceptions", async () => {
			mockProjectsClient.get.mockRejectedValue("Unknown error");

			const result = await checkOsLoginEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Unknown error");
		});
	});
});
