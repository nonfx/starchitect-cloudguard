// @ts-nocheck
import { CloudFrontClient, ListDistributionsCommand } from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontCustomSSLCertificate from "./check-cloudfront-custom-ssl-certificate";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistributionWithCustomCert = {
	Id: "DIST1",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DIST1",
	ViewerCertificate: {
		CloudFrontDefaultCertificate: false,
		ACMCertificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/custom-cert"
	}
};

const mockDistributionWithDefaultCert = {
	Id: "DIST2",
	ARN: "arn:aws:cloudfront::123456789012:distribution/DIST2",
	ViewerCertificate: {
		CloudFrontDefaultCertificate: true
	}
};

describe("checkCloudFrontCustomSSLCertificate", () => {
	beforeEach(() => {
		mockCloudFrontClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when distribution uses custom SSL certificate", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithCustomCert]
				}
			});

			const result = await checkCloudFrontCustomSSLCertificate.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("DIST1");
			expect(result.checks[0].resourceArn).toBe(mockDistributionWithCustomCert.ARN);
		});

		it("should handle multiple compliant distributions", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithCustomCert, mockDistributionWithCustomCert]
				}
			});

			const result = await checkCloudFrontCustomSSLCertificate.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when distribution uses default SSL certificate", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithDefaultCert]
				}
			});

			const result = await checkCloudFrontCustomSSLCertificate.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("using the default SSL/TLS certificate");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [mockDistributionWithCustomCert, mockDistributionWithDefaultCert]
				}
			});

			const result = await checkCloudFrontCustomSSLCertificate.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no distributions exist", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: { Items: [] }
			});

			const result = await checkCloudFrontCustomSSLCertificate.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFront distributions found");
		});

		it("should handle distributions without ID or ARN", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({
				DistributionList: {
					Items: [{ ViewerCertificate: { CloudFrontDefaultCertificate: true } }]
				}
			});

			const result = await checkCloudFrontCustomSSLCertificate.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Distribution found without ID or ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).rejects(new Error("API Error"));

			const result = await checkCloudFrontCustomSSLCertificate.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudFront distributions");
		});

		it("should handle undefined DistributionList", async () => {
			mockCloudFrontClient.on(ListDistributionsCommand).resolves({});

			const result = await checkCloudFrontCustomSSLCertificate.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
