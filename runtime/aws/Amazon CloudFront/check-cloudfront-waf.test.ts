// @ts-nocheck
import { CloudFrontClient, ListDistributionsCommand } from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontWaf from "./check-cloudfront-waf";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistributionWithWaf = {
    Id: "DISTRIBUTION1",
    ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION1",
    WebACLId: "waf-acl-1"
};

const mockDistributionWithoutWaf = {
    Id: "DISTRIBUTION2",
    ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION2",
    WebACLId: ""
};

describe("checkCloudFrontWaf", () => {
    beforeEach(() => {
        mockCloudFrontClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when distribution has WAF enabled", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistributionWithWaf]
                }
            });

            const result = await checkCloudFrontWaf.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("DISTRIBUTION1");
            expect(result.checks[0].resourceArn).toBe(mockDistributionWithWaf.ARN);
        });

        it("should return NOTAPPLICABLE when no distributions exist", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: []
                }
            });

            const result = await checkCloudFrontWaf.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No CloudFront distributions found");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when distribution has no WAF", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistributionWithoutWaf]
                }
            });

            const result = await checkCloudFrontWaf.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("CloudFront distribution does not have WAF enabled");
        });

        it("should handle mixed WAF configurations", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistributionWithWaf, mockDistributionWithoutWaf]
                }
            });

            const result = await checkCloudFrontWaf.execute();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });

        it("should handle distributions without Id or ARN", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [{ WebACLId: "waf-1" }]
                }
            });

            const result = await checkCloudFrontWaf.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Distribution found without ID or ARN");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).rejects(
                new Error("API Error")
            );

            const result = await checkCloudFrontWaf.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Error checking CloudFront distributions: API Error");
        });

        it("should handle undefined DistributionList", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({});

            const result = await checkCloudFrontWaf.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No CloudFront distributions found");
        });
    });
});