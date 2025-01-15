// @ts-nocheck
import { Storage } from "@google-cloud/storage";
import { ComplianceStatus } from "../../types.js";
import checkStorageBucketPublicAccess from "./check-storage-bucket-public-access";

describe("checkStorageBucketPublicAccess", () => {
	let mockGetBuckets;
	let mockGetPolicy;

	beforeEach(() => {
		mockGetPolicy = jest.fn();
		mockGetBuckets = jest.fn();

		// Setup default mocks
		Storage.prototype.getBuckets = mockGetBuckets;
		mockGetBuckets.mockResolvedValue([[]]); // Default: empty bucket list

		// Setup IAM policy mock
		const mockBucket = {
			name: "test-bucket",
			iam: {
				getPolicy: mockGetPolicy
			}
		};
		mockGetPolicy.mockResolvedValue([{ bindings: [] }]);
	});

	describe("Compliant Resources", () => {
		it("should return PASS when bucket has no public access", async () => {
			const mockBucket = {
				name: "private-bucket",
				iam: {
					getPolicy: jest.fn().mockResolvedValue([
						{
							bindings: [
								{
									members: ["user:test@example.com"],
									role: "roles/storage.objectViewer"
								}
							]
						}
					])
				}
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkStorageBucketPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("private-bucket");
		});

		it("should handle multiple private buckets", async () => {
			const mockBuckets = [
				{
					name: "private-bucket-1",
					iam: {
						getPolicy: jest.fn().mockResolvedValue([
							{
								bindings: [
									{
										members: ["serviceAccount:test@example.com"],
										role: "roles/storage.admin"
									}
								]
							}
						])
					}
				},
				{
					name: "private-bucket-2",
					iam: {
						getPolicy: jest.fn().mockResolvedValue([
							{
								bindings: [
									{
										members: ["group:team@example.com"],
										role: "roles/storage.objectViewer"
									}
								]
							}
						])
					}
				}
			];

			mockGetBuckets.mockResolvedValue([mockBuckets]);

			const result = await checkStorageBucketPublicAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when bucket allows allUsers access", async () => {
			const mockBucket = {
				name: "public-bucket",
				iam: {
					getPolicy: jest.fn().mockResolvedValue([
						{
							bindings: [
								{
									members: ["allUsers"],
									role: "roles/storage.objectViewer"
								}
							]
						}
					])
				}
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkStorageBucketPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Bucket has public access through IAM policy");
		});

		it("should return FAIL when bucket allows allAuthenticatedUsers access", async () => {
			const mockBucket = {
				name: "authenticated-public-bucket",
				iam: {
					getPolicy: jest.fn().mockResolvedValue([
						{
							bindings: [
								{
									members: ["allAuthenticatedUsers"],
									role: "roles/storage.objectViewer"
								}
							]
						}
					])
				}
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkStorageBucketPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Bucket has public access through IAM policy");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockGetBuckets.mockResolvedValue([[]]);

			const result = await checkStorageBucketPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No storage buckets found in the project");
		});

		it("should handle empty IAM policy", async () => {
			const mockBucket = {
				name: "empty-policy-bucket",
				iam: {
					getPolicy: jest.fn().mockResolvedValue([{}])
				}
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkStorageBucketPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when getBuckets fails", async () => {
			mockGetBuckets.mockRejectedValue(new Error("API Error"));

			const result = await checkStorageBucketPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking storage buckets");
		});

		it("should return ERROR when getPolicy fails", async () => {
			const mockBucket = {
				name: "error-bucket",
				iam: {
					getPolicy: jest.fn().mockRejectedValue(new Error("IAM Error"))
				}
			};

			mockGetBuckets.mockResolvedValue([[mockBucket]]);

			const result = await checkStorageBucketPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking bucket IAM policy");
		});

		it("should handle non-Error exceptions", async () => {
			mockGetBuckets.mockRejectedValue("Unknown error");

			const result = await checkStorageBucketPublicAccess.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Unknown error");
		});
	});
});
