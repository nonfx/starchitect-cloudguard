// @ts-nocheck
import { CloudFrontClient, ListDistributionsCommand } from "@aws-sdk/client-cloudfront";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFrontDefaultRootObject from "./check-cloudfront-default-root-object";

const mockCloudFrontClient = mockClient(CloudFrontClient);

const mockDistributionWithDefaultRoot = {
    Id: "DISTRIBUTION1",
    ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION1",
    DefaultRootObject: "index.html"
};

const mockDistributionWithoutDefaultRoot = {
    Id: "DISTRIBUTION2",
    ARN: "arn:aws:cloudfront::123456789012:distribution/DISTRIBUTION2",
    DefaultRootObject: ""
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

            const result = await checkCloudFrontDefaultRootObject.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe(
                "CloudFront distribution does not have a default root object configured"
            );
        });

        it("should handle mixed compliance states", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [
                        mockDistributionWithDefaultRoot,
                        mockDistributionWithoutDefaultRoot
                    ]
                }
            });

            const result = await checkCloudFrontDefaultRootObject.execute();
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });

        it("should handle distributions without Id or ARN", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({
                DistributionList: {
                    Items: [{ DefaultRootObject: "index.html" }]
                }
            });

            const result = await checkCloudFrontDefaultRootObject.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Distribution found without ID or ARN");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).rejects(
                new Error("API Error")
            );

            const result = await checkCloudFrontDefaultRootObject.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe(
                "Error checking CloudFront distributions: API Error"
            );
        });

        it("should handle missing DistributionList", async () => {
            mockCloudFrontClient.on(ListDistributionsCommand).resolves({});

            const result = await checkCloudFrontDefaultRootObject.execute();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
        });
    });
});