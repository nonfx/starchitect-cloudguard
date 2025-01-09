// @ts-nocheck
import {
	DocDBClient,
	DescribeDBClustersCommand,
	DescribeDBInstancesCommand
} from "@aws-sdk/client-docdb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDocDBSecurityAssessments from "./check-docdb-security-assessments";

const mockDocDBClient = mockClient(DocDBClient);

const mockCompliantCluster = {
	DBClusterIdentifier: "compliant-cluster",
	DBClusterArn: "arn:aws:docdb:us-east-1:123456789012:cluster:compliant-cluster",
	StorageEncrypted: true,
	DeletionProtection: true,
	VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-123" }]
};

const mockNonCompliantCluster = {
	DBClusterIdentifier: "non-compliant-cluster",
	DBClusterArn: "arn:aws:docdb:us-east-1:123456789012:cluster:non-compliant-cluster",
	StorageEncrypted: false,
	DeletionProtection: false,
	VpcSecurityGroups: []
};

describe("checkDocDBSecurityAssessments", () => {
	beforeEach(() => {
		mockDocDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for clusters with proper security configurations", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCompliantCluster] });
			mockDocDBClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });

			const result = await checkDocDBSecurityAssessments.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-cluster");
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });

			const result = await checkDocDBSecurityAssessments.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DocumentDB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for clusters with missing security configurations", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockNonCompliantCluster] });
			mockDocDBClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });

			const result = await checkDocDBSecurityAssessments.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Cluster missing required security configurations");
		});

		it("should handle multiple clusters with mixed compliance", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCompliantCluster, mockNonCompliantCluster] });
			mockDocDBClient.on(DescribeDBInstancesCommand).resolves({ DBInstances: [] });

			const result = await checkDocDBSecurityAssessments.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when DescribeDBClusters fails", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkDocDBSecurityAssessments.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DocumentDB clusters");
		});

		it("should handle clusters without identifiers", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [{}] });

			const result = await checkDocDBSecurityAssessments.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without identifier or ARN");
		});

		it("should handle DescribeDBInstances failures for specific clusters", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCompliantCluster] });
			mockDocDBClient.on(DescribeDBInstancesCommand).rejects(new Error("Instance API Error"));

			const result = await checkDocDBSecurityAssessments.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});
});
