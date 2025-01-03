// @ts-nocheck
import {
	CloudFrontClient,
	ListDistributionsCommand,
	GetDistributionCommand
} from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontDefaultRootObject from "./check-cloudfront-default-root-object";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistributionWithDefaultRoot = {
	Id: "DISTRIBUTION1",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION1"
};

const mockDistributionWithoutDefaultRoot = {
	Id: "DISTRIBUTION2",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION2"
};

describe("checkCloudFrontDefaultRootObject", () => {
	beforeEach(() => {
		mockCloudFrontClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when distribution has default root object", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithDefaultRoot]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						DefaultRootObject: "index.html"
					}
				}
			});

			const result = await checkCloudFrontDefaultRootObject.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("DISTRIBUTION1");
			expect(result.checks[0].resourceArn).toBe(mockDistributionWithDefaultRoot.ARN);
		});

		it("should return NOTAPPLICABLE when no distributions exist", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: []
				}
			});

			const result = await checkCloudFrontDefaultRootObject.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFront distributions found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when distribution has no default root object", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithoutDefaultRoot]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						DefaultRootObject: ""
					}
				}
			});

			const result = await checkCloudFrontDefaultRootObject.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"CloudFront distribution does not have a default root object configured"
			);
		});

		it("should handle mixed compliance states", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithDefaultRoot, mockDistributionWithoutDefaultRoot]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand, { Id: "DISTRIBUTION1" }).resolves({
				Distribution: {
					DistributionConfig: {
						DefaultRootObject: "index.html"
					}
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand, { Id: "DISTRIBUTION2" }).resolves({
				Distribution: {
					DistributionConfig: {
						DefaultRootObject: ""
					}
				}
			});

			const result = await checkCloudFrontDefaultRootObject.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).rejects(new Error("API Error"));

			const result = await checkCloudFrontDefaultRootObject.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking CloudFront distributions: API Error");
		});

		it("should return ERROR when GetDistribution fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithDefaultRoot]
				}
			});

			mockCloudFrontClient
				.on(GetDistributionCommand)
				.rejects(new Error("Failed to get distribution"));

			const result = await checkCloudFrontDefaultRootObject.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error retrieving distribution details");
		});

		it("should handle distributions without Id or ARN", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [{}] // Empty distribution object
				}
			});

			const result = await checkCloudFrontDefaultRootObject.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Distribution found without ID or ARN");
		});

		it("should handle missing configuration", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithDefaultRoot]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {} // Empty distribution configuration
			});

			const result = await checkCloudFrontDefaultRootObject.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to get distribution configuration");
		});
	});
});
