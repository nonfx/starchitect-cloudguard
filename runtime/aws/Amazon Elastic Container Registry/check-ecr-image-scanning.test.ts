import { ECRClient, DescribeRepositoriesCommand } from "@aws-sdk/client-ecr";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkEcrImageScanningCompliance from "./check-ecr-image-scanning";

const mockEcrClient = mockClient(ECRClient);

const mockCompliantRepo = {
    repositoryName: "compliant-repo",
    repositoryArn: "arn:aws:ecr:us-east-1:123456789012:repository/compliant-repo",
    imageScanningConfiguration: {
        scanOnPush: true
    }
};

const mockNonCompliantRepo = {
    repositoryName: "non-compliant-repo",
    repositoryArn: "arn:aws:ecr:us-east-1:123456789012:repository/non-compliant-repo",
    imageScanningConfiguration: {
        scanOnPush: false
    }
};

describe("checkEcrImageScanningCompliance", () => {
    beforeEach(() => {
        mockEcrClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when image scanning is enabled", async () => {
            mockEcrClient.on(DescribeRepositoriesCommand).resolves({
                repositories: [mockCompliantRepo]
            });

            const result = await checkEcrImageScanningCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("compliant-repo");
            expect(result.checks[0].resourceArn).toBe(mockCompliantRepo.repositoryArn);
        });

        it("should return NOTAPPLICABLE when no repositories exist", async () => {
            mockEcrClient.on(DescribeRepositoriesCommand).resolves({
                repositories: []
            });

            const result = await checkEcrImageScanningCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No ECR repositories found in the region");
        });

        it("should handle multiple compliant repositories", async () => {
            mockEcrClient.on(DescribeRepositoriesCommand).resolves({
                repositories: [mockCompliantRepo, mockCompliantRepo]
            });

            const result = await checkEcrImageScanningCompliance("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when image scanning is disabled", async () => {
            mockEcrClient.on(DescribeRepositoriesCommand).resolves({
                repositories: [mockNonCompliantRepo]
            });

            const result = await checkEcrImageScanningCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Image scanning is not enabled for this repository");
        });

        it("should handle mixed compliance status", async () => {
            mockEcrClient.on(DescribeRepositoriesCommand).resolves({
                repositories: [mockCompliantRepo, mockNonCompliantRepo]
            });

            const result = await checkEcrImageScanningCompliance("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });

        it("should handle repository without scanning configuration", async () => {
            const repoWithoutConfig = {
                repositoryName: "no-config-repo",
                repositoryArn: "arn:aws:ecr:us-east-1:123456789012:repository/no-config-repo",
                imageScanningConfiguration: undefined
            };

            mockEcrClient.on(DescribeRepositoriesCommand).resolves({
                repositories: [repoWithoutConfig]
            });

            const result = await checkEcrImageScanningCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockEcrClient.on(DescribeRepositoriesCommand).rejects(new Error("API Error"));

            const result = await checkEcrImageScanningCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking ECR repositories: API Error");
        });

        it("should handle repository without name or ARN", async () => {
            const invalidRepo = {
                imageScanningConfiguration: { scanOnPush: true }
            };

            mockEcrClient.on(DescribeRepositoriesCommand).resolves({
                repositories: [invalidRepo]
            });

            const result = await checkEcrImageScanningCompliance("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Repository found without name or ARN");
        });
    });
});