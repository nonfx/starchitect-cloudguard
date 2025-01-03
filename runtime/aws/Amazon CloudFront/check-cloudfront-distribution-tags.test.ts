// @ts-nocheck
import {
	CloudFrontClient,
	ListDistributionsCommand,
	ListTagsForResourceCommand
} from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontDistributionTags from "./check-cloudfront-distribution-tags";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistribution = {
	Id: "DISTRIBUTION123",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION123"
};

describe("checkCloudFrontDistributionTags", () => {
	beforeEach(() => {
		mockCloudFrontClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when distribution has user-defined tags", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(ListTagsForResourceCommand).resolves({
				Tags: {
					Items: [
						{ Key: "Environment", Value: "Production" },
						{ Key: "Owner", Value: "TeamA" }
					]
				}
			});

			const result = await checkCloudFrontDistributionTags.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockDistribution.Id);
			expect(result.checks[0].resourceArn).toBe(mockDistribution.ARN);
		});

		it("should ignore system tags starting with aws:", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(ListTagsForResourceCommand).resolves({
				Tags: {
					Items: [
						{ Key: "aws:created", Value: "system" },
						{ Key: "Environment", Value: "Production" }
					]
				}
			});

			const result = await checkCloudFrontDistributionTags.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when distribution has no tags", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(ListTagsForResourceCommand).resolves({
				Tags: { Items: [] }
			});

			const result = await checkCloudFrontDistributionTags.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("CloudFront distribution has no user-defined tags");
		});

		it("should return FAIL when distribution only has system tags", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(ListTagsForResourceCommand).resolves({
				Tags: {
					Items: [{ Key: "aws:created", Value: "system" }]
				}
			});

			const result = await checkCloudFrontDistributionTags.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no distributions exist", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: { Items: [] }
			});

			const result = await checkCloudFrontDistributionTags.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFront distributions found");
		});

		it("should return ERROR when ListDistributions fails", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.rejects(new Error("Failed to list distributions"));

			const result = await checkCloudFrontDistributionTags.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list distributions");
		});

		it("should return ERROR when ListTagsForResource fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(ListTagsForResourceCommand).rejects(new Error("Access denied"));

			const result = await checkCloudFrontDistributionTags.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking tags");
		});

		it("should handle distributions without Id or ARN", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [{}] // Empty distribution object
				}
			});

			const result = await checkCloudFrontDistributionTags.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Distribution found without ID or ARN");
		});
	});
});
