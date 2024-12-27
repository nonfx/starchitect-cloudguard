//@ts-nocheck
import { EC2Client, DescribeVpcsCommand, type Vpc } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkVpcExists from "./check-vpc-exists";

const mockEC2Client = mockClient(EC2Client);

const mockDefaultVpc: Vpc = {
	VpcId: "vpc-12345",
	OwnerId: "123456789012",
	IsDefault: true,
	State: "available"
};

const mockCustomVpc: Vpc = {
	VpcId: "vpc-67890",
	OwnerId: "123456789012",
	IsDefault: false,
	State: "available"
};

describe("checkVpcExists", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when default VPC exists", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [mockDefaultVpc]
			});

			const result = await checkVpcExists.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("vpc-12345");
			expect(result.checks[0]?.message).toBe("Default VPC exists");
			expect(result.checks[0]?.resourceArn).toBe(
				"arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345"
			);
		});

		test("should return PASS when custom VPC exists", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [mockCustomVpc]
			});

			const result = await checkVpcExists.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.message).toBe("Custom VPC exists");
		});

		test("should handle multiple VPCs", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [mockDefaultVpc, mockCustomVpc]
			});

			const result = await checkVpcExists.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when no VPCs exist", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: []
			});

			const result = await checkVpcExists.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("No VPCs found in the region");
		});

		test("should handle VPCs without VpcId", async () => {
			const incompleteVpc: Vpc = {
				IsDefault: true
			};

			mockEC2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [incompleteVpc]
			});

			const result = await checkVpcExists.execute();
			expect(result.checks).toHaveLength(0);
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeVpcsCommand).rejects(new Error("API call failed"));

			const result = await checkVpcExists.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking VPCs: API call failed");
		});

		test("should handle non-Error exceptions", async () => {
			mockEC2Client.on(DescribeVpcsCommand).rejects("String error");

			const result = await checkVpcExists.execute();
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Error checking VPCs: String error");
		});
	});

	describe("Region Handling", () => {
		test("should use default region", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [mockDefaultVpc]
			});

			const result = await checkVpcExists.execute();
			expect(result.checks[0]?.resourceArn).toContain("us-east-1");
		});
	});
});
