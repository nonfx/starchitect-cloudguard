// @ts-nocheck
import { DocDBClient, DescribeDBInstancesCommand, DescribeDBClustersCommand } from "@aws-sdk/client-docdb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDocDBUpdates from "./check-docdb-updates";

const mockDocDBClient = mockClient(DocDBClient);

const mockCluster = {
    DBClusterIdentifier: "test-cluster-1",
    DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-1"
};

const mockCompliantInstance = {
    DBInstanceIdentifier: "test-instance-1",
    DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-instance-1",
    PendingModifiedValues: {},
    AutoMinorVersionUpgrade: true
};

const mockNonCompliantInstance = {
    DBInstanceIdentifier: "test-instance-2",
    DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-instance-2",
    PendingModifiedValues: { Engine: "pending-update" },
    AutoMinorVersionUpgrade: false
};

describe("checkDocDBUpdates", () => {
    beforeEach(() => {
        mockDocDBClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for instances with no pending updates and auto minor version upgrade enabled", async () => {
            mockDocDBClient
                .on(DescribeDBClustersCommand)
                .resolves({ DBClusters: [mockCluster] });
            mockDocDBClient
                .on(DescribeDBInstancesCommand)
                .resolves({ DBInstances: [mockCompliantInstance] });

            const result = await checkDocDBUpdates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("test-instance-1");
        });

        it("should return NOTAPPLICABLE when no DocumentDB clusters exist", async () => {
            mockDocDBClient
                .on(DescribeDBClustersCommand)
                .resolves({ DBClusters: [] });

            const result = await checkDocDBUpdates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No DocumentDB clusters found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for instances with pending updates", async () => {
            mockDocDBClient
                .on(DescribeDBClustersCommand)
                .resolves({ DBClusters: [mockCluster] });
            mockDocDBClient
                .on(DescribeDBInstancesCommand)
                .resolves({ DBInstances: [mockNonCompliantInstance] });

            const result = await checkDocDBUpdates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("pending maintenance updates");
        });

        it("should return FAIL for instances with auto minor version upgrade disabled", async () => {
            const instanceWithoutAutoUpgrade = {
                ...mockCompliantInstance,
                AutoMinorVersionUpgrade: false
            };

            mockDocDBClient
                .on(DescribeDBClustersCommand)
                .resolves({ DBClusters: [mockCluster] });
            mockDocDBClient
                .on(DescribeDBInstancesCommand)
                .resolves({ DBInstances: [instanceWithoutAutoUpgrade] });

            const result = await checkDocDBUpdates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Auto minor version upgrade is not enabled");
        });

        it("should return FAIL for clusters with no instances", async () => {
            mockDocDBClient
                .on(DescribeDBClustersCommand)
                .resolves({ DBClusters: [mockCluster] });
            mockDocDBClient
                .on(DescribeDBInstancesCommand)
                .resolves({ DBInstances: [] });

            const result = await checkDocDBUpdates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("No instances found in the cluster");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when DescribeDBClusters fails", async () => {
            mockDocDBClient
                .on(DescribeDBClustersCommand)
                .rejects(new Error("API Error"));

            const result = await checkDocDBUpdates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking DocumentDB clusters");
        });

        it("should return ERROR when DescribeDBInstances fails", async () => {
            mockDocDBClient
                .on(DescribeDBClustersCommand)
                .resolves({ DBClusters: [mockCluster] });
            mockDocDBClient
                .on(DescribeDBInstancesCommand)
                .rejects(new Error("API Error"));

            const result = await checkDocDBUpdates.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking cluster instances");
        });
    });

    it("should handle multiple instances with mixed compliance status", async () => {
        mockDocDBClient
            .on(DescribeDBClustersCommand)
            .resolves({ DBClusters: [mockCluster] });
        mockDocDBClient
            .on(DescribeDBInstancesCommand)
            .resolves({ 
                DBInstances: [
                    mockCompliantInstance,
                    mockNonCompliantInstance
                ] 
            });

        const result = await checkDocDBUpdates.execute("us-east-1");
        expect(result.checks).toHaveLength(2);
        expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
        expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
    });
});