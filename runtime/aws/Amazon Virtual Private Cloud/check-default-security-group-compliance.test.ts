// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { EC2Client, DescribeVpcsCommand, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkDefaultSecurityGroupCompliance from "./check-default-security-group-compliance";

const mockEC2Client = mockClient(EC2Client);

const mockCompliantSecurityGroup = {
	GroupId: "sg-12345",
	GroupName: "default",
	OwnerId: "123456789012",
	IpPermissions: [],
	IpPermissionsEgress: [
		{
			IpRanges: [{ CidrIp: "127.0.0.1/32" }]
		}
	]
};

const mockNonCompliantSecurityGroup = {
	GroupId: "sg-67890",
	GroupName: "default",
	OwnerId: "123456789012",
	IpPermissions: [
		{
			IpProtocol: "-1",
			FromPort: -1,
			ToPort: -1,
			IpRanges: [{ CidrIp: "0.0.0.0/0" }]
		}
	],
	IpPermissionsEgress: [
		{
			IpProtocol: "-1",
			FromPort: -1,
			ToPort: -1,
			IpRanges: [{ CidrIp: "0.0.0.0/0" }]
		}
	]
};

describe("checkDefaultSecurityGroupCompliance", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for VPC with compliant default security group", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: "vpc-12345" }] });
			mockEC2Client
				.on(DescribeSecurityGroupsCommand)
				.resolves({ SecurityGroups: [mockCompliantSecurityGroup] });

			const result = await checkDefaultSecurityGroupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("vpc-12345");
		});

		it("should return PASS for security group with self-referencing rule", async () => {
			const selfReferencingSG = {
				...mockCompliantSecurityGroup,
				IpPermissions: [
					{
						UserIdGroupPairs: [{ GroupId: "sg-12345" }]
					}
				]
			};

			mockEC2Client.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: "vpc-12345" }] });
			mockEC2Client
				.on(DescribeSecurityGroupsCommand)
				.resolves({ SecurityGroups: [selfReferencingSG] });

			const result = await checkDefaultSecurityGroupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for VPC with non-compliant default security group", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: "vpc-67890" }] });
			mockEC2Client
				.on(DescribeSecurityGroupsCommand)
				.resolves({ SecurityGroups: [mockNonCompliantSecurityGroup] });

			const result = await checkDefaultSecurityGroupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Default security group has unauthorized rules");
		});

		it("should handle multiple VPCs with mixed compliance", async () => {
			mockEC2Client
				.on(DescribeVpcsCommand)
				.resolves({ Vpcs: [{ VpcId: "vpc-12345" }, { VpcId: "vpc-67890" }] });
			mockEC2Client
				.on(DescribeSecurityGroupsCommand)
				.resolves({ SecurityGroups: [mockCompliantSecurityGroup] })
				.on(DescribeSecurityGroupsCommand, {
					Filters: [
						{ Name: "vpc-id", Values: ["vpc-67890"] },
						{ Name: "group-name", Values: ["default"] }
					]
				})
				.resolves({ SecurityGroups: [mockNonCompliantSecurityGroup] });

			const result = await checkDefaultSecurityGroupCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no VPCs exist", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({ Vpcs: [] });

			const result = await checkDefaultSecurityGroupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No VPCs found in the region");
		});

		it("should return ERROR when VPC API call fails", async () => {
			mockEC2Client.on(DescribeVpcsCommand).rejects(new Error("API Error"));

			const result = await checkDefaultSecurityGroupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking VPCs");
		});

		it("should return ERROR when security group not found", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({ Vpcs: [{ VpcId: "vpc-12345" }] });
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({ SecurityGroups: [] });

			const result = await checkDefaultSecurityGroupCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Default security group not found");
		});
	});
});
