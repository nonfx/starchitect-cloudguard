// @ts-nocheck
import { APIGatewayClient, GetStagesCommand, GetRestApisCommand } from "@aws-sdk/client-api-gateway";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkApiGatewaySslCertificates from "./check-api-gateway-ssl-certificates";

const mockApiGatewayClient = mockClient(APIGatewayClient);

const mockApi = {
    id: "abc123",
    name: "test-api"
};

const mockStageWithCert = {
    stageName: "prod",
    clientCertificateId: "cert123"
};

const mockStageWithoutCert = {
    stageName: "dev",
    clientCertificateId: undefined
};

describe("checkApiGatewaySslCertificates", () => {
    beforeEach(() => {
        mockApiGatewayClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when stages have SSL certificates configured", async () => {
            mockApiGatewayClient
                .on(GetRestApisCommand)
                .resolves({ items: [mockApi] });
            mockApiGatewayClient
                .on(GetStagesCommand)
                .resolves({ item: [mockStageWithCert] });

            const result = await checkApiGatewaySslCertificates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("test-api/prod (abc123)");
        });

        it("should handle multiple compliant stages", async () => {
            mockApiGatewayClient
                .on(GetRestApisCommand)
                .resolves({ items: [mockApi] });
            mockApiGatewayClient
                .on(GetStagesCommand)
                .resolves({ item: [mockStageWithCert, mockStageWithCert] });

            const result = await checkApiGatewaySslCertificates.execute("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when stages don't have SSL certificates", async () => {
            mockApiGatewayClient
                .on(GetRestApisCommand)
                .resolves({ items: [mockApi] });
            mockApiGatewayClient
                .on(GetStagesCommand)
                .resolves({ item: [mockStageWithoutCert] });

            const result = await checkApiGatewaySslCertificates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe(
                "Stage does not have an SSL certificate configured for backend authentication"
            );
        });

        it("should handle mixed compliance scenarios", async () => {
            mockApiGatewayClient
                .on(GetRestApisCommand)
                .resolves({ items: [mockApi] });
            mockApiGatewayClient
                .on(GetStagesCommand)
                .resolves({ item: [mockStageWithCert, mockStageWithoutCert] });

            const result = await checkApiGatewaySslCertificates.execute("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Edge Cases", () => {
        it("should return NOTAPPLICABLE when no APIs exist", async () => {
            mockApiGatewayClient
                .on(GetRestApisCommand)
                .resolves({ items: [] });

            const result = await checkApiGatewaySslCertificates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No API Gateway REST APIs found in the region");
        });

        it("should return NOTAPPLICABLE when API has no stages", async () => {
            mockApiGatewayClient
                .on(GetRestApisCommand)
                .resolves({ items: [mockApi] });
            mockApiGatewayClient
                .on(GetStagesCommand)
                .resolves({ item: [] });

            const result = await checkApiGatewaySslCertificates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No stages found for this REST API");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when GetRestApis fails", async () => {
            mockApiGatewayClient
                .on(GetRestApisCommand)
                .rejects(new Error("API Error"));

            const result = await checkApiGatewaySslCertificates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking API Gateway");
        });

        it("should return ERROR when GetStages fails", async () => {
            mockApiGatewayClient
                .on(GetRestApisCommand)
                .resolves({ items: [mockApi] });
            mockApiGatewayClient
                .on(GetStagesCommand)
                .rejects(new Error("Stage Error"));

            const result = await checkApiGatewaySslCertificates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking stages");
        });
    });
});