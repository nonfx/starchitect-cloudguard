// @ts-nocheck
import { MemoryDBClient, DescribeClustersCommand } from "@aws-sdk/client-memorydb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkMemoryDBNetworkSecurity from "./check-memorydb-network-security";

const mockMemoryDBClient = mockClient(MemoryDBClient);

const mockCompliantCluster = {
	Name: "test-cluster-1",
	ARN: "arn:aws:memorydb:us-east-1:123456789012:cluster/test-cluster-1",
	SubnetGroupName: "subnet-group-1",
	SecurityGroups: ["sg-12345678"]
};

const mockNonCompliantCluster = {
	Name: "test-cluster-2",
	ARN: "arn:aws:memorydb:us-east-1:123456789012:cluster/test-cluster-2",
	SubnetGroupName: null,
	SecurityGroups: []
};

describe("checkMemoryDBNetworkSecurity", () => {
	beforeEach(() => {
		mockMemoryDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when cluster has proper network security configuration", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: [mockCompliantCluster]
			});

			const result = await checkMemoryDBNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-cluster-1");
			expect(result.checks[0].resourceArn).toBe(mockCompliantCluster.ARN);
		});

		it("should return NOTAPPLICABLE when no clusters exist", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: []
			});

			const result = await checkMemoryDBNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No MemoryDB clusters found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when cluster lacks subnet group and security groups", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: [mockNonCompliantCluster]
			});

			const result = await checkMemoryDBNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Network security is not properly enabled for this Amazon MemoryDB cluster"
			);
		});

		it("should handle clusters with missing names", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: [{ ARN: "test-arn" }]
			});

			const result = await checkMemoryDBNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Cluster found without name");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({
				Clusters: [mockCompliantCluster, mockNonCompliantCluster]
			});

			const result = await checkMemoryDBNetworkSecurity.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).rejects(new Error("API Error"));

			const result = await checkMemoryDBNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking MemoryDB clusters");
		});

		it("should handle undefined Clusters response", async () => {
			mockMemoryDBClient.on(DescribeClustersCommand).resolves({});

			const result = await checkMemoryDBNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});
	});
});
