//@ts-nocheck
import {
	CloudFrontClient,
	ListDistributionsCommand,
	GetDistributionCommand
} from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontOAC from "./check-cloudfront-oac";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistribution = {
	Id: "DISTRIBUTION1",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION1",
	DomainName: "d123.cloudfront.net"
};

const mockS3Origin = {
	DomainName: "mybucket.s3.amazonaws.com",
	Id: "S3-mybucket",
	OriginAccessControlId: "OACID123"
};

const mockNonS3Origin = {
	DomainName: "example.com",
	Id: "CustomOrigin1"
};

describe("checkCloudFrontOAC", () => {
	beforeEach(() => {
		mockCloudFrontClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when S3 origins use OAC", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						Origins: {
							Items: [mockS3Origin]
						}
					}
				}
			});

			const result = await checkCloudFrontOAC.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("DISTRIBUTION1");
		});

		it("should return NOTAPPLICABLE for distributions without S3 origins", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						Origins: {
							Items: [mockNonS3Origin]
						}
					}
				}
			});

			const result = await checkCloudFrontOAC.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("Distribution does not have S3 origins");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when S3 origins don't use OAC", async () => {
			const s3OriginWithoutOAC = { ...mockS3Origin, OriginAccessControlId: undefined };

			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						Origins: {
							Items: [s3OriginWithoutOAC]
						}
					}
				}
			});

			const result = await checkCloudFrontOAC.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"S3 origin(s) do not have Origin Access Control configured"
			);
		});

		it("should handle mixed S3 origins with and without OAC", async () => {
			const s3OriginWithoutOAC = { ...mockS3Origin, OriginAccessControlId: undefined };

			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).resolves({
				Distribution: {
					DistributionConfig: {
						Origins: {
							Items: [mockS3Origin, s3OriginWithoutOAC]
						}
					}
				}
			});

			const result = await checkCloudFrontOAC.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no distributions exist", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: []
				}
			});

			const result = await checkCloudFrontOAC.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFront distributions found");
		});

		it("should return ERROR when ListDistributions fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).rejects(new Error("API Error"));

			const result = await checkCloudFrontOAC.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudFront distributions");
		});

		it("should return ERROR when GetDistribution fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistribution]
				}
			});

			mockCloudFrontClient.on(GetDistributionCommand).rejects(new Error("API Error"));

			const result = await checkCloudFrontOAC.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking distribution");
		});
	});
});
