// @ts-nocheck
import { EC2Client, DescribeVpcEndpointsCommand } from "@aws-sdk/client-ec2";
import { DynamoDBClient, ListTablesCommand } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDynamoDBVPCEndpoint from "./check-dynamodb-vpc-endpoint";

const mockEC2Client = mockClient(EC2Client);
const mockDynamoDBClient = mockClient(DynamoDBClient);

const mockVpcEndpoint = {
	VpcEndpointId: "vpce-1234567890abcdef0",
	ServiceName: "com.amazonaws.us-east-1.dynamodb",
	State: "available"
};

describe("checkDynamoDBVPCEndpoint", () => {
	beforeEach(() => {
		mockEC2Client.reset();
		mockDynamoDBClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when DynamoDB tables have VPC endpoint configured", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: ["table1", "table2"]
			});
			mockEC2Client.on(DescribeVpcEndpointsCommand).resolves({
				VpcEndpoints: [mockVpcEndpoint]
			});

			const result = await checkDynamoDBVPCEndpoint.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no DynamoDB tables exist", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: []
			});

			const result = await checkDynamoDBVPCEndpoint.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No DynamoDB tables found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no VPC endpoint is configured", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: ["table1", "table2"]
			});
			mockEC2Client.on(DescribeVpcEndpointsCommand).resolves({
				VpcEndpoints: []
			});

			const result = await checkDynamoDBVPCEndpoint.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("No VPC endpoint for DynamoDB is configured");
		});

		it("should handle multiple tables with no VPC endpoint", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: ["table1", "table2", "table3"]
			});
			mockEC2Client.on(DescribeVpcEndpointsCommand).resolves({
				VpcEndpoints: []
			});

			const result = await checkDynamoDBVPCEndpoint.execute("us-east-1");
			expect(result.checks).toHaveLength(3);
			result.checks.forEach(check => {
				expect(check.status).toBe(ComplianceStatus.FAIL);
			});
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListTables fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).rejects(new Error("Failed to list tables"));

			const result = await checkDynamoDBVPCEndpoint.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list tables");
		});

		it("should return ERROR when DescribeVpcEndpoints fails", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: ["table1"]
			});
			mockEC2Client
				.on(DescribeVpcEndpointsCommand)
				.rejects(new Error("Failed to describe VPC endpoints"));

			const result = await checkDynamoDBVPCEndpoint.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to describe VPC endpoints");
		});
	});

	describe("Region Handling", () => {
		it("should use provided region for endpoint check", async () => {
			mockDynamoDBClient.on(ListTablesCommand).resolves({
				TableNames: ["table1"]
			});
			mockEC2Client.on(DescribeVpcEndpointsCommand).resolves({
				VpcEndpoints: [mockVpcEndpoint]
			});

			const result = await checkDynamoDBVPCEndpoint.execute("eu-west-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});
});
