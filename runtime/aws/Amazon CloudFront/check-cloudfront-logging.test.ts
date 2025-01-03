// @ts-nocheck
import { CloudFrontClient, ListDistributionsCommand, GetDistributionCommand } from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontLogging from "./check-cloudfront-logging";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistribution = {
    Id: "DISTRIBUTION1",
    ARN: "arn:aws:cloudfront::DISTRIBUTION1",
    Status: "Deployed",
    DomainName: "example.cloudfront.net"
};

describe("checkCloudFrontLogging", () => {
    beforeEach(() => {
        mockCloudFrontClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when logging is enabled on distribution", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistribution],
                    Quantity: 1
                }
            });

            mockCloudFrontClient.on(GetDistributionCommand).resolves({
                Distribution: {
                    DistributionConfig: {
                        Logging: {
                            Bucket: "logging-bucket.s3.amazonaws.com",
                            Enabled: true
                        }
                    }
                }
            });

            const result = await checkCloudFrontLogging.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("DISTRIBUTION1");
        });

        it("should return NOTAPPLICABLE when no distributions exist", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [],
                    Quantity: 0
                }
            });

            const result = await checkCloudFrontLogging.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No CloudFront distributions found");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when logging is disabled", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistribution],
                    Quantity: 1
                }
            });

            mockCloudFrontClient.on(GetDistributionCommand).resolves({
                Distribution: {
                    DistributionConfig: {
                        Logging: {
                            Bucket: "",
                            Enabled: false
                        }
                    }
                }
            });

            const result = await checkCloudFrontLogging.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("CloudFront distribution does not have logging enabled");
        });

        it("should handle multiple distributions with mixed compliance", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [
                        { ...mockDistribution, Id: "DIST1" },
                        { ...mockDistribution, Id: "DIST2" }
                    ],
                    Quantity: 2
                }
            });

            mockCloudFrontClient
                .on(GetDistributionCommand)
                .resolvesOnce({
                    Distribution: {
                        DistributionConfig: {
                            Logging: {
                                Bucket: "logging-bucket.s3.amazonaws.com",
                                Enabled: true
                            }
                        }
                    }
                })
                .resolvesOnce({
                    Distribution: {
                        DistributionConfig: {
                            Logging: {
                                Bucket: "",
                                Enabled: false
                            }
                        }
                    }
                });

            const result = await checkCloudFrontLogging.execute();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when ListDistributions fails", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).rejects(
                new Error("Failed to list distributions")
            );

            const result = await checkCloudFrontLogging.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking CloudFront distributions");
        });

        it("should return ERROR when GetDistribution fails", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [mockDistribution],
                    Quantity: 1
                }
            });

            mockCloudFrontClient.on(GetDistributionCommand).rejects(
                new Error("Failed to get distribution config")
            );

            const result = await checkCloudFrontLogging.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking distribution");
        });

        it("should handle distribution without ID", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [{ ...mockDistribution, Id: undefined }],
                    Quantity: 1
                }
            });

            const result = await checkCloudFrontLogging.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Distribution found without ID");
        });
    });
});