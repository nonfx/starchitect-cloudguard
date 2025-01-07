// @ts-nocheck
import {
	DocDBClient,
	DescribeDBClustersCommand,
	DescribeDBClusterParameterGroupsCommand
} from "@aws-sdk/client-docdb";
import { IAMClient, GetRoleCommand, ListAttachedRolePoliciesCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDocDBAuthAccessControl from "./check-docdb-auth-access-control";

const mockDocDBClient = mockClient(DocDBClient);
const mockIAMClient = mockClient(IAMClient);

const mockCompliantCluster = {
	DBClusterIdentifier: "compliant-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:compliant-cluster",
	EnableIAMDatabaseAuthentication: true,
	AssociatedRoles: [
		{
			RoleArn: "arn:aws:iam::123456789012:role/docdb-role"
		}
	],
	DBClusterParameterGroup: "default.docdb4.0"
};

const mockNonCompliantCluster = {
	DBClusterIdentifier: "non-compliant-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:non-compliant-cluster",
	EnableIAMDatabaseAuthentication: false,
	AssociatedRoles: [],
	DBClusterParameterGroup: "default.docdb4.0"
};

describe("checkDocDBAuthAccessControl", () => {
	beforeEach(() => {
		mockDocDBClient.reset();
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for properly configured cluster", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCompliantCluster] })
				.on(DescribeDBClusterParameterGroupsCommand)
				.resolves({
					DBClusterParameterGroups: [{ DBClusterParameterGroupName: "default.docdb4.0" }]
				});

			mockIAMClient
				.on(GetRoleCommand)
				.resolves({ Role: { RoleName: "docdb-role" } })
				.on(ListAttachedRolePoliciesCommand)
				.resolves({ AttachedPolicies: [{ PolicyName: "DocDBPolicy" }] });

			const result = await checkDocDBAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-cluster");
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });

			const result = await checkDocDBAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DocumentDB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for cluster without IAM authentication", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockNonCompliantCluster] })
				.on(DescribeDBClusterParameterGroupsCommand)
				.resolves({
					DBClusterParameterGroups: [{ DBClusterParameterGroupName: "default.docdb4.0" }]
				});

			const result = await checkDocDBAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("does not have proper authentication");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCompliantCluster, mockNonCompliantCluster] })
				.on(DescribeDBClusterParameterGroupsCommand)
				.resolves({
					DBClusterParameterGroups: [{ DBClusterParameterGroupName: "default.docdb4.0" }]
				});

			mockIAMClient
				.on(GetRoleCommand)
				.resolves({ Role: { RoleName: "docdb-role" } })
				.on(ListAttachedRolePoliciesCommand)
				.resolves({ AttachedPolicies: [{ PolicyName: "DocDBPolicy" }] });

			const result = await checkDocDBAuthAccessControl.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when DescribeDBClusters fails", async () => {
			mockDocDBClient.on(DescribeDBClustersCommand).rejects(new Error("API Error"));

			const result = await checkDocDBAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DocumentDB clusters");
		});

		it("should handle errors for individual cluster checks", async () => {
			mockDocDBClient
				.on(DescribeDBClustersCommand)
				.resolves({ DBClusters: [mockCompliantCluster] })
				.on(DescribeDBClusterParameterGroupsCommand)
				.rejects(new Error("Parameter group error"));

			const result = await checkDocDBAuthAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking cluster configuration");
		});
	});
});
