//@ts-nocheck
import {
	IAMClient,
	ListPoliciesCommand,
	GetPolicyVersionCommand,
	type Policy
} from "@aws-sdk/client-iam";
import { RDSClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAuroraIamRolesAndPolicies from "./check-aurora-iam-roles-and-policies";

const mockIAMClient = mockClient(IAMClient);
const mockRDSClient = mockClient(RDSClient);

const mockCluster: DBCluster = {
	DBClusterIdentifier: "test-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster"
};

const mockPolicies: Policy[] = [
	{
		PolicyName: "RDSFullAccess",
		Arn: "arn:aws:iam::123456789012:policy/RDSFullAccess",
		DefaultVersionId: "v1"
	}
];

const validPolicyDocument = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: ["rds:*"],
			Resource: ["arn:aws:rds:*:*:*"]
		}
	]
};

const invalidPolicyDocument = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: ["s3:*"],
			Resource: ["*"]
		}
	]
};

describe("checkAuroraIamRolesAndPolicies", () => {
	beforeEach(() => {
		mockIAMClient.reset();
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when proper RDS policies exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster]
			});

			mockIAMClient
				.on(ListPoliciesCommand)
				.resolves({ Policies: mockPolicies })
				.on(GetPolicyVersionCommand)
				.resolves({
					PolicyVersion: {
						Document: encodeURIComponent(JSON.stringify(validPolicyDocument))
					}
				});

			const result = await checkAuroraIamRolesAndPolicies.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster");
		});

		it("should return NOTAPPLICABLE when no Aurora clusters exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({ DBClusters: [] });

			const result = await checkAuroraIamRolesAndPolicies.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Aurora clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no valid RDS policies exist", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster]
			});

			mockIAMClient
				.on(ListPoliciesCommand)
				.resolves({ Policies: mockPolicies })
				.on(GetPolicyVersionCommand)
				.resolves({
					PolicyVersion: {
						Document: encodeURIComponent(JSON.stringify(invalidPolicyDocument))
					}
				});

			const result = await checkAuroraIamRolesAndPolicies.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No valid IAM policy found that grants access to this RDS cluster"
			);
		});

		it("should handle multiple clusters with mixed compliance", async () => {
			const cluster2: DBCluster = {
				...mockCluster,
				DBClusterIdentifier: "test-cluster-2",
				DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster-2"
			};

			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster, cluster2]
			});

			mockIAMClient
				.on(ListPoliciesCommand)
				.resolves({ Policies: mockPolicies })
				.on(GetPolicyVersionCommand)
				.resolves({
					PolicyVersion: {
						Document: encodeURIComponent(JSON.stringify(validPolicyDocument))
					}
				});

			const result = await checkAuroraIamRolesAndPolicies.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when IAM API calls fail", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).resolves({
				DBClusters: [mockCluster]
			});
			mockIAMClient.on(ListPoliciesCommand).rejects(new Error("IAM API Error"));

			const result = await checkAuroraIamRolesAndPolicies.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("IAM API Error");
		});

		it("should return ERROR when RDS API calls fail", async () => {
			mockRDSClient.on(DescribeDBClustersCommand).rejects(new Error("RDS API Error"));

			const result = await checkAuroraIamRolesAndPolicies.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking IAM configuration");
		});
	});
});
