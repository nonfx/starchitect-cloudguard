// @ts-nocheck
import { DocDBClient, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDocDBEncryptionInTransit from "./check-docdb-encryption-in-transit";

const mockDocDBClient = mockClient(DocDBClient);

const mockEncryptedCluster = {
    DBClusterIdentifier: "encrypted-cluster",
    DBClusterArn: "arn:aws:docdb:us-east-1:123456789012:cluster:encrypted-cluster",
    StorageEncrypted: true
};

const mockUnencryptedCluster = {
    DBClusterIdentifier: "unencrypted-cluster",
    DBClusterArn: "arn:aws:docdb:us-east-1:123456789012:cluster:unencrypted-cluster",
    StorageEncrypted: false
};

describe("checkDocDBEncryptionInTransit", () => {
    beforeEach(() => {
        mockDocDBClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when all clusters have encryption enabled", async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({
                DBClusters: [mockEncryptedCluster]
            });

            const result = await checkDocDBEncryptionInTransit.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("encrypted-cluster");
            expect(result.checks[0].resourceArn).toBe(mockEncryptedCluster.DBClusterArn);
        });

        it("should return NOTAPPLICABLE when no clusters exist", async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({
                DBClusters: []
            });

            const result = await checkDocDBEncryptionInTransit.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No DocumentDB clusters found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when clusters have encryption disabled", async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({
                DBClusters: [mockUnencryptedCluster]
            });

            const result = await checkDocDBEncryptionInTransit.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Encryption in transit is not enabled for this DocumentDB cluster");
        });

        it("should handle mixed encryption states", async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({
                DBClusters: [mockEncryptedCluster, mockUnencryptedCluster]
            });

            const result = await checkDocDBEncryptionInTransit.execute("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });

        it("should handle clusters without identifiers", async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({
                DBClusters: [{ StorageEncrypted: true }]
            });

            const result = await checkDocDBEncryptionInTransit.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

            const result = await checkDocDBEncryptionInTransit.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Error checking DocumentDB clusters: API Error");
        });

        it("should handle undefined DBClusters response", async () => {
            mockDocDBClient.on(DescribeDBClustersCommand).resolves({});

            const result = await checkDocDBEncryptionInTransit.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
        });
    });
});