import { CloudTrailClient, ListTrailsCommand, GetTrailCommand } from "@aws-sdk/client-cloudtrail";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkCloudTrailTagged from "./check-cloudtrail-tagged";

const mockCloudTrailClient = mockClient(CloudTrailClient);

const mockTrails = [
    {
        Name: "test-trail-1",
        TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail-1"
    },
    {
        Name: "test-trail-2",
        TrailARN: "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail-2"
    }
];

describe("checkCloudTrailTagged", () => {
    beforeEach(() => {
        mockCloudTrailClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when trails have user-defined tags", async () => {
            mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: mockTrails });
            mockCloudTrailClient.on(GetTrailCommand).resolves({
                Trail: {
                    ...mockTrails[0],
                    Tags: {
                        Environment: "production",
                        Owner: "team-a"
                    }
                }
            });

            const result = await checkCloudTrailTagged("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("test-trail-1");
        });

        it("should ignore system tags starting with 'aws:'", async () => {
            mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [mockTrails[0]] });
            mockCloudTrailClient.on(GetTrailCommand).resolves({
                Trail: {
                    ...mockTrails[0],
                    Tags: {
                        "aws:createdBy": "system",
                        Environment: "production"
                    }
                }
            });

            const result = await checkCloudTrailTagged("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when trails have no user-defined tags", async () => {
            mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [mockTrails[0]] });
            mockCloudTrailClient.on(GetTrailCommand).resolves({
                Trail: {
                    ...mockTrails[0],
                    Tags: {}
                }
            });

            const result = await checkCloudTrailTagged("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("CloudTrail trail does not have any user-defined tags");
        });

        it("should return FAIL when trails only have system tags", async () => {
            mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [mockTrails[0]] });
            mockCloudTrailClient.on(GetTrailCommand).resolves({
                Trail: {
                    ...mockTrails[0],
                    Tags: {
                        "aws:createdBy": "system"
                    }
                }
            });

            const result = await checkCloudTrailTagged("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return NOTAPPLICABLE when no trails exist", async () => {
            mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [] });

            const result = await checkCloudTrailTagged("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No CloudTrail trails found in the region");
        });

        it("should return ERROR when ListTrails fails", async () => {
            mockCloudTrailClient.on(ListTrailsCommand).rejects(new Error("API Error"));

            const result = await checkCloudTrailTagged("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking CloudTrail trails");
        });

        it("should return ERROR for trail without ARN", async () => {
            mockCloudTrailClient.on(ListTrailsCommand).resolves({
                Trails: [{ Name: "invalid-trail" }]
            });

            const result = await checkCloudTrailTagged("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Trail found without ARN");
        });

        it("should handle GetTrail API errors", async () => {
            mockCloudTrailClient.on(ListTrailsCommand).resolves({ Trails: [mockTrails[0]] });
            mockCloudTrailClient.on(GetTrailCommand).rejects(new Error("Access Denied"));

            const result = await checkCloudTrailTagged("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking trail tags");
        });
    });
});