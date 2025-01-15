// @ts-nocheck
import { Storage } from "@google-cloud/storage";
import { ComplianceStatus } from "../../types.js";
import checkStorageBucketRetention from "./check-storage-bucket-retention";

describe("checkStorageBucketRetention", () => {
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
		mockGetMetadata.mockResolvedValue([{}]); // Default: no retention policy
	});

	describe("Compliant Resources", () => {
		it("should return PASS when bucket has valid retention policy with lock enabled", async () => {
			const mockBucket = {
				name: "compliant-bucket",
				getMetadata: jest.fn().mockResolvedValue([
					{
						retentionPolicy: {
							isLocked: true,
							retentionPeriod: "86400" // 1 day in seconds
						}
					}
				])
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkStorageBucketRetention.execute();
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
							retentionPolicy: {
								isLocked: true,
								retentionPeriod: "86400"
							}
						}
					])
				},
				{
					name: "compliant-bucket-2",
					getMetadata: jest.fn().mockResolvedValue([
						{
							retentionPolicy: {
								isLocked: true,
								retentionPeriod: "172800" // 2 days in seconds
							}
						}
					])
				}
			];

			mockGetBuckets.mockResolvedValue([mockBuckets]);

			const result = await checkStorageBucketRetention.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when retention policy is not locked", async () => {
			const mockBucket = {
				name: "non-compliant-bucket",
				getMetadata: jest.fn().mockResolvedValue([
					{
						retentionPolicy: {
							isLocked: false,
							retentionPeriod: "86400"
						}
					}
				])
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkStorageBucketRetention.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain(
				"must have a retention policy configured with Bucket Lock enabled"
			);
		});

		it("should return FAIL when retention period is 0", async () => {
			const mockBucket = {
				name: "zero-retention-bucket",
				getMetadata: jest.fn().mockResolvedValue([
					{
						retentionPolicy: {
							isLocked: true,
							retentionPeriod: "0"
						}
					}
				])
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkStorageBucketRetention.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain(
				"must have a retention policy configured with Bucket Lock enabled"
			);
		});

		it("should return FAIL when retention policy is missing", async () => {
			const mockBucket = {
				name: "no-retention-bucket",
				getMetadata: jest.fn().mockResolvedValue([{}])
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkStorageBucketRetention.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain(
				"must have a retention policy configured with Bucket Lock enabled"
			);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockGetBuckets.mockResolvedValue([[]]);

			const result = await checkStorageBucketRetention.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No storage buckets found in the project");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when getBuckets fails", async () => {
			mockGetBuckets.mockRejectedValue(new Error("API Error"));

			const result = await checkStorageBucketRetention.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking storage buckets");
		});

		it("should return ERROR when getMetadata fails", async () => {
			const mockBucket = {
				name: "error-bucket",
				getMetadata: jest.fn().mockRejectedValue(new Error("Metadata Error"))
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkStorageBucketRetention.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking bucket retention policy");
		});

		it("should handle non-Error exceptions", async () => {
			mockGetBuckets.mockRejectedValue("Unknown error");

			const result = await checkStorageBucketRetention.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Unknown error");
		});
	});
});
