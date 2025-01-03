// @ts-nocheck
import {
	CloudFrontClient,
	ListDistributionsCommand,
	GetDistributionCommand
} from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontEncryption from "./check-cloudfront-encryption.js";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistribution = {
	Id: "DISTRIBUTION1",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION1"
};

describe("checkCloudFrontEncryption", () => {
	beforeEach(() => {
		mockCloudFrontClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when distribution uses HTTPS only", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						DefaultCacheBehavior: {
							ViewerProtocolPolicy: "https-only"
						},
						CacheBehaviors: {
							Items: [{ ViewerProtocolPolicy: "https-only" }]
						}
					}
				}
			});

			const result = await checkCloudFrontEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceArn).toBe(mockDistribution.ARN);
		});

		it("should return PASS when distribution redirects to HTTPS", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						DefaultCacheBehavior: {
							ViewerProtocolPolicy: "redirect-to-https"
						}
					}
				}
			});

			const result = await checkCloudFrontEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when distribution allows unencrypted traffic", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						DefaultCacheBehavior: {
							ViewerProtocolPolicy: "allow-all"
						}
					}
				}
			});

			const result = await checkCloudFrontEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("allows unencrypted traffic");
		});

		it("should return FAIL when any cache behavior allows unencrypted traffic", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						DefaultCacheBehavior: {
							ViewerProtocolPolicy: "https-only"
						},
						CacheBehaviors: {
							Items: [{ ViewerProtocolPolicy: "allow-all" }]
						}
					}
				}
			});

			const result = await checkCloudFrontEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no distributions exist", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: []
				}
			});

			const result = await checkCloudFrontEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFront distributions found");
		});

		it("should return ERROR when distribution config is missing", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: null
				}
			});

			const result = await checkCloudFrontEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Could not retrieve distribution configuration");
		});

		it("should return ERROR when API calls fail", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).rejects(new Error("API Error"));

			const result = await checkCloudFrontEncryption.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error listing distributions");
		});
	});
});
