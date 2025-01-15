// @ts-nocheck
import { ServiceUsageClient } from "@google-cloud/service-usage";
import { ComplianceStatus } from "../../types.js";
import checkCloudAssetInventoryEnabled from "./gcp-cloud-asset-inventory.js";

describe("checkCloudAssetInventoryEnabled", () => {
	let mockServiceUsageClient;

	beforeEach(() => {
		// Create mock client
		mockServiceUsageClient = {
			getService: jest.fn().mockResolvedValue([[]])
		};

		// Mock the client's constructor
		jest
			.spyOn(ServiceUsageClient.prototype, "getService")
			.mockImplementation(mockServiceUsageClient.getService);
	});

	afterEach(() => {
		jest.restoreAllMocks();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Cloud Asset Inventory API is enabled", async () => {
			const mockService = {
				name: "projects/test-project/services/cloudasset.googleapis.com",
				state: "ENABLED"
			};

			mockServiceUsageClient.getService.mockResolvedValue([mockService]);

			const result = await checkCloudAssetInventoryEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("Cloud Asset Inventory API");
			expect(result.checks[0]?.resourceArn).toBe(
				"projects/test-project/services/cloudasset.googleapis.com"
			);
			expect(result.checks[0]?.message).toBeUndefined();
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Cloud Asset Inventory API is disabled", async () => {
			const mockService = {
				name: "projects/test-project/services/cloudasset.googleapis.com",
				state: "DISABLED"
			};

			mockServiceUsageClient.getService.mockResolvedValue([mockService]);

			const result = await checkCloudAssetInventoryEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Cloud Asset Inventory API is not enabled");
		});

		it("should return FAIL when service is not found", async () => {
			mockServiceUsageClient.getService.mockRejectedValue(new Error("Service not found"));

			const result = await checkCloudAssetInventoryEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Cloud Asset Inventory API is not enabled");
		});
	});

	describe("Edge Cases", () => {
		it("should return ERROR when project ID is not provided", async () => {
			const result = await checkCloudAssetInventoryEnabled.execute("");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Project ID is not provided");
		});

		it("should correctly format service name in request", async () => {
			const mockService = {
				state: "ENABLED"
			};

			mockServiceUsageClient.getService.mockResolvedValue([mockService]);

			await checkCloudAssetInventoryEnabled.execute("test-project");

			expect(mockServiceUsageClient.getService).toHaveBeenCalledWith({
				name: "projects/test-project/services/cloudasset.googleapis.com"
			});
		});
	});

	describe("Error Handling", () => {
		it("should handle permission denied errors", async () => {
			mockServiceUsageClient.getService.mockRejectedValue(new Error("Permission denied"));

			const result = await checkCloudAssetInventoryEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Insufficient permissions");
		});

		it("should handle general API errors", async () => {
			mockServiceUsageClient.getService.mockRejectedValue(new Error("API Error"));

			const result = await checkCloudAssetInventoryEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking Cloud Asset Inventory status");
		});

		it("should handle non-Error exceptions", async () => {
			mockServiceUsageClient.getService.mockRejectedValue("Unknown error");

			const result = await checkCloudAssetInventoryEnabled.execute("test-project");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Unknown error");
		});
	});
});
