// @ts-nocheck
import { Storage } from "@google-cloud/storage";
import { ComplianceStatus } from "../../types.js";
import checkUniformBucketLevelAccess from "./check-uniform-bucket-level-access";

describe("checkUniformBucketLevelAccess", () => {
	let mockGetBuckets;
	let mockGetMetadata;

	beforeEach(() => {
		mockGetMetadata = jest.fn();
		mockGetBuckets = jest.fn();

		// Setup default mocks
		Storage.prototype.getBuckets = mockGetBuckets;
		mockGetBuckets.mockResolvedValue([[]]); // Default: empty bucket list

		// Setup metadata mock
		const mockBucket = {
			name: "test-bucket",
			getMetadata: mockGetMetadata
		};
		mockGetMetadata.mockResolvedValue([{}]); // Default: no IAM configuration
	});

	describe("Compliant Resources", () => {
		it("should return PASS when uniform bucket-level access is enabled", async () => {
			const mockBucket = {
				name: "compliant-bucket",
				getMetadata: jest.fn().mockResolvedValue([
					{
						iamConfiguration: {
							uniformBucketLevelAccess: {
								enabled: true
							}
						}
					}
				])
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkUniformBucketLevelAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("compliant-bucket");
		});

		it("should handle multiple compliant buckets", async () => {
			const mockBuckets = [
				{
					name: "compliant-bucket-1",
					getMetadata: jest.fn().mockResolvedValue([
						{
							iamConfiguration: {
								uniformBucketLevelAccess: {
									enabled: true
								}
							}
						}
					])
				},
				{
					name: "compliant-bucket-2",
					getMetadata: jest.fn().mockResolvedValue([
						{
							iamConfiguration: {
								uniformBucketLevelAccess: {
									enabled: true
								}
							}
						}
					])
				}
			];

			mockGetBuckets.mockResolvedValue([mockBuckets]);

			const result = await checkUniformBucketLevelAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when uniform bucket-level access is disabled", async () => {
			const mockBucket = {
				name: "non-compliant-bucket",
				getMetadata: jest.fn().mockResolvedValue([
					{
						iamConfiguration: {
							uniformBucketLevelAccess: {
								enabled: false
							}
						}
					}
				])
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkUniformBucketLevelAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"Uniform bucket-level access is not enabled for this bucket"
			);
		});

		it("should handle mixed compliance results", async () => {
			const mockBuckets = [
				{
					name: "compliant-bucket",
					getMetadata: jest.fn().mockResolvedValue([
						{
							iamConfiguration: {
								uniformBucketLevelAccess: {
									enabled: true
								}
							}
						}
					])
				},
				{
					name: "non-compliant-bucket",
					getMetadata: jest.fn().mockResolvedValue([
						{
							iamConfiguration: {
								uniformBucketLevelAccess: {
									enabled: false
								}
							}
						}
					])
				}
			];

			mockGetBuckets.mockResolvedValue([mockBuckets]);

			const result = await checkUniformBucketLevelAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockGetBuckets.mockResolvedValue([[]]);

			const result = await checkUniformBucketLevelAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No Cloud Storage buckets found");
		});

		it("should handle missing iamConfiguration", async () => {
			const mockBucket = {
				name: "no-iam-config-bucket",
				getMetadata: jest.fn().mockResolvedValue([{}])
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkUniformBucketLevelAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"Uniform bucket-level access is not enabled for this bucket"
			);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when getBuckets fails", async () => {
			const errorMessage = "Failed to list buckets";
			mockGetBuckets.mockRejectedValue(new Error(errorMessage));

			const result = await checkUniformBucketLevelAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(
				`Error checking Cloud Storage buckets: ${errorMessage}`
			);
		});

		it("should return ERROR for specific bucket when getMetadata fails", async () => {
			const errorMessage = "Access denied";
			const mockBucket = {
				name: "error-bucket",
				getMetadata: jest.fn().mockRejectedValue(new Error(errorMessage))
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkUniformBucketLevelAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe(`Error checking bucket metadata: ${errorMessage}`);
		});

		it("should handle non-Error exceptions", async () => {
			mockGetBuckets.mockRejectedValue("Unknown error");

			const result = await checkUniformBucketLevelAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Unknown error");
		});
	});
});
