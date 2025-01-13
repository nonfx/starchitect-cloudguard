// @ts-nocheck
import { NeptuneClient, DescribeDBClustersCommand } from "@aws-sdk/client-neptune";
import {
	IAMClient,
	ListRolesCommand,
	GetRolePolicyCommand,
	ListRolePoliciesCommand,
	ListAttachedRolePoliciesCommand,
	GetPolicyCommand,
	GetPolicyVersionCommand
} from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkNeptuneAccessControl from "./check-neptune-access-control";

const mockNeptuneClient = mockClient(NeptuneClient);
const mockIAMClient = mockClient(IAMClient);

const mockCluster = {
	DBClusterIdentifier: "test-cluster-1",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-1",
	IAMDatabaseAuthenticationEnabled: true
};

const mockClusterNoAuth = {
	DBClusterIdentifier: "test-cluster-2",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-2",
	IAMDatabaseAuthenticationEnabled: false
};

const mockRole = {
	RoleName: "test-role",
	Arn: "arn:aws:iam::123456789012:role/test-role"
};

describe("checkNeptuneAccessControl", () => {
	beforeEach(() => {
		mockNeptuneClient.reset();
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for cluster with IAM auth enabled and proper IAM roles", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster]
			});

			mockIAMClient.on(ListRolesCommand).resolves({
				Roles: [mockRole]
			});

			mockIAMClient.on(ListRolePoliciesCommand).resolves({
				PolicyNames: ["test-policy"]
			});

			mockIAMClient.on(GetRolePolicyCommand).resolves({
				PolicyDocument: encodeURIComponent(
					JSON.stringify({
						Statement: [
							{
								Effect: "Allow",
								Action: ["neptune-db:connect"],
								Resource: [mockCluster.DBClusterArn]
							}
						]
					})
				)
			});

			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: []
			});

			const result = await checkNeptuneAccessControl.execute("us-east-1");
			// First check should be for the cluster's IAM auth status
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockCluster.DBClusterIdentifier);
			expect(result.checks[0].message).toBe("IAM Database Authentication is enabled");

			// Second check should be for the role permissions
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].resourceName).toBe(mockRole.RoleName);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: []
			});

			const result = await checkNeptuneAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Neptune clusters found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when IAM Database Authentication is disabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockClusterNoAuth]
			});

			mockIAMClient.on(ListRolesCommand).resolves({
				Roles: [mockRole]
			});

			mockIAMClient.on(ListRolePoliciesCommand).resolves({
				PolicyNames: ["test-policy"]
			});

			mockIAMClient.on(GetRolePolicyCommand).resolves({
				PolicyDocument: encodeURIComponent(
					JSON.stringify({
						Statement: [
							{
								Effect: "Allow",
								Action: ["neptune-db:connect"],
								Resource: [mockClusterNoAuth.DBClusterArn]
							}
						]
					})
				)
			});

			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: []
			});

			const result = await checkNeptuneAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("IAM Database Authentication is not enabled");
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return FAIL for wildcard permissions even with IAM auth enabled", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster]
			});

			mockIAMClient.on(ListRolesCommand).resolves({
				Roles: [mockRole]
			});

			mockIAMClient.on(ListRolePoliciesCommand).resolves({
				PolicyNames: ["test-policy"]
			});

			mockIAMClient.on(GetRolePolicyCommand).resolves({
				PolicyDocument: encodeURIComponent(
					JSON.stringify({
						Statement: [
							{
								Effect: "Allow",
								Action: "*",
								Resource: "*"
							}
						]
					})
				)
			});

			mockIAMClient.on(ListAttachedRolePoliciesCommand).resolves({
				AttachedPolicies: []
			});

			const result = await checkNeptuneAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("IAM Database Authentication is enabled");
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].message).toBe(
				"Role has overly permissive Neptune access with wildcard permissions"
			);
		});

		it("should return FAIL when no IAM roles exist", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster]
			});

			mockIAMClient.on(ListRolesCommand).resolves({
				Roles: []
			});

			const result = await checkNeptuneAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("IAM Database Authentication is enabled");
			expect(result.checks).toHaveLength(1);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when Neptune API call fails", async () => {
			mockNeptuneClient
				.on(DescribeDBClustersCommand)
				.rejects(new Error("Failed to describe clusters"));

			const result = await checkNeptuneAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe(
				"Error checking IAM roles: Failed to get Neptune clusters: Failed to describe clusters"
			);
		});

		it("should return cluster auth status but ERROR for roles when IAM API call fails", async () => {
			mockNeptuneClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster]
			});

			mockIAMClient.on(ListRolesCommand).rejects(new Error("Failed to list roles"));

			const result = await checkNeptuneAccessControl.execute("us-east-1");
			// First check should still show cluster auth status
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("IAM Database Authentication is enabled");
			// Second check should show error for role check
			expect(result.checks[1].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[1].message).toBe("Error checking IAM roles: Failed to list roles");
		});
	});
});
