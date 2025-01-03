// @ts-nocheck
import { CloudFrontClient, ListDistributionsCommand, GetDistributionCommand } from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontSslProtocols from "./check-cloudfront-ssl-protocols";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistribution = {
    Id: "DISTRIBUTION1",
    ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION1"
};

describe("checkCloudFrontSslProtocols", () => {
    beforeEach(() => {
        mockCloudFrontClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when custom origins use secure protocols", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistribution]
                }
            });

            mockCloudFrontClient.on(GetDistributionCommand).resolves({
                Distribution: {
                    DistributionConfig: {
                        Origins: {
                            Items: [{
                                CustomOriginConfig: {
                                    OriginSslProtocols: {
                                        Items: ["TLSv1.2"]
                                    }
                                }
                            }]
                        }
                    }
                }
            });

            const result = await checkCloudFrontSslProtocols.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("DISTRIBUTION1");
        });

        it("should return NOTAPPLICABLE when distribution has no custom origins", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistribution]
                }
            });

            mockCloudFrontClient.on(GetDistributionCommand).resolves({
                Distribution: {
                    DistributionConfig: {
                        Origins: {
                            Items: [{
                                // S3 origin without CustomOriginConfig
                            }]
                        }
                    }
                }
            });

            const result = await checkCloudFrontSslProtocols.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when SSLv3 is used", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistribution]
                }
            });

            mockCloudFrontClient.on(GetDistributionCommand).resolves({
                Distribution: {
                    DistributionConfig: {
                        Origins: {
                            Items: [{
                                CustomOriginConfig: {
                                    OriginSslProtocols: {
                                        Items: ["SSLv3", "TLSv1.2"]
                                    }
                                }
                            }]
                        }
                    }
                }
            });

            const result = await checkCloudFrontSslProtocols.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("deprecated SSLv3 protocol");
        });

        it("should handle multiple origins with mixed protocols", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistribution]
                }
            });

            mockCloudFrontClient.on(GetDistributionCommand).resolves({
                Distribution: {
                    DistributionConfig: {
                        Origins: {
                            Items: [
                                {
                                    CustomOriginConfig: {
                                        OriginSslProtocols: {
                                            Items: ["TLSv1.2"]
                                        }
                                    }
                                },
                                {
                                    CustomOriginConfig: {
                                        OriginSslProtocols: {
                                            Items: ["SSLv3"]
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            });

            const result = await checkCloudFrontSslProtocols.execute();
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

            const result = await checkCloudFrontSslProtocols.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No CloudFront distributions found");
        });

        it("should return ERROR when ListDistributions fails", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).rejects(
                new Error("API Error")
            );

            const result = await checkCloudFrontSslProtocols.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking CloudFront distributions");
        });

        it("should return ERROR when GetDistribution fails", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistribution]
                }
            });

            mockCloudFrontClient.on(GetDistributionCommand).rejects(
                new Error("Access Denied")
            );

            const result = await checkCloudFrontSslProtocols.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking distribution");
        });
    });
});