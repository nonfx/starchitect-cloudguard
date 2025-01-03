// @ts-nocheck
import {
	CloudFrontClient,
	ListDistributionsCommand,
	GetDistributionCommand
} from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontCustomOriginEncryption from "./check-cloudfront-custom-origin-encryption";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistribution = {
	Id: "DISTRIBUTION1",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION1"
};

const mockCompliantConfig = {
	Distribution: {
		DistributionConfig: {
			Origins: {
				Items: [
					{
						CustomOriginConfig: {
							OriginProtocolPolicy: "https-only"
						}
					}
				]
			},
			DefaultCacheBehavior: {
				ViewerProtocolPolicy: "https-only"
			}
		}
	}
};

const mockNonCompliantHttpOnlyConfig = {
	Distribution: {
		DistributionConfig: {
			Origins: {
				Items: [
					{
						CustomOriginConfig: {
							OriginProtocolPolicy: "http-only"
						}
					}
				]
			}
		}
	}
};

const mockNonCompliantMatchViewerConfig = {
	Distribution: {
		DistributionConfig: {
			Origins: {
				Items: [
					{
						CustomOriginConfig: {
							OriginProtocolPolicy: "match-viewer"
						}
					}
				]
			},
			DefaultCacheBehavior: {
				ViewerProtocolPolicy: "allow-all"
			}
		}
	}
};

describe("checkCloudFrontCustomOriginEncryption", () => {
	beforeEach(() => {
		mockCloudFrontClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for distribution with HTTPS-only configuration", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [mockDistribution] } });
			mockCloudFrontClient.on(GetDistributionCommand).resolves(mockCompliantConfig);

			const result = await checkCloudFrontCustomOriginEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceArn).toBe(mockDistribution.ARN);
		});

		it("should return NOTAPPLICABLE when no distributions exist", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [] } });

			const result = await checkCloudFrontCustomOriginEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFront distributions found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for distribution with http-only protocol policy", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [mockDistribution] } });
			mockCloudFrontClient.on(GetDistributionCommand).resolves(mockNonCompliantHttpOnlyConfig);

			const result = await checkCloudFrontCustomOriginEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Distribution uses http-only origin protocol policy");
		});

		it("should return FAIL for distribution with match-viewer and allow-all configuration", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [mockDistribution] } });
			mockCloudFrontClient.on(GetDistributionCommand).resolves(mockNonCompliantMatchViewerConfig);

			const result = await checkCloudFrontCustomOriginEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Distribution uses match-viewer origin protocol policy with allow-all viewer protocol policy"
			);
		});

		it("should handle multiple distributions with mixed compliance", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [
						{
							...mockDistribution,
							Id: "DIST1",
							ARN: "arn:aws:cloudfront::123456789012:distribution/DIST1"
						},
						{
							...mockDistribution,
							Id: "DIST2",
							ARN: "arn:aws:cloudfront::123456789012:distribution/DIST2"
						}
					]
				}
			});

			// Set up different responses based on the distribution ID
			mockCloudFrontClient
				.on(GetDistributionCommand, { Id: "DIST1" })
				.resolves(mockCompliantConfig);

			mockCloudFrontClient
				.on(GetDistributionCommand, { Id: "DIST2" })
				.resolves(mockNonCompliantHttpOnlyConfig);

			const result = await checkCloudFrontCustomOriginEncryption.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListDistributions fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).rejects(new Error("API Error"));

			const result = await checkCloudFrontCustomOriginEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudFront distributions");
		});

		it("should return ERROR when GetDistribution fails", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [mockDistribution] } });
			mockCloudFrontClient.on(GetDistributionCommand).rejects(new Error("Access Denied"));

			const result = await checkCloudFrontCustomOriginEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking distribution");
		});

		it("should handle missing distribution configuration", async () => {
			mockCloudFrontClient
				.on(ListDistributionsCommand)
				.resolves({ DistributionList: { Items: [mockDistribution] } });
			mockCloudFrontClient.on(GetDistributionCommand).resolves({ Distribution: {} });

			const result = await checkCloudFrontCustomOriginEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to retrieve distribution configuration");
		});
	});
});
