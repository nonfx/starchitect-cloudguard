// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkSecurityGroupAdminPorts from "./check-security-group-admin-ports";

const mockEC2Client = mockClient(EC2Client);

const mockCompliantSG = {
	GroupId: "sg-compliant",
	GroupName: "compliant-sg",
	OwnerId: "123456789012",
	IpPermissions: [
		{
			FromPort: 22,
			ToPort: 22,
			IpRanges: [{ CidrIp: "10.0.0.0/8" }]
		}
	]
};

const mockNonCompliantSG = {
	GroupId: "sg-non-compliant",
	GroupName: "non-compliant-sg",
	OwnerId: "123456789012",
	IpPermissions: [
		{
			FromPort: 22,
			ToPort: 22,
			IpRanges: [{ CidrIp: "0.0.0.0/0" }]
		}
	]
};

const mockMixedSG = {
	GroupId: "sg-mixed",
	GroupName: "mixed-sg",
	OwnerId: "123456789012",
	IpPermissions: [
		{
			FromPort: 3389,
			ToPort: 3389,
			IpRanges: [{ CidrIp: "0.0.0.0/0" }],
			Ipv6Ranges: [{ CidrIpv6: "::/0" }]
		}
	]
};

describe("checkSecurityGroupAdminPorts", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for security groups with no open admin ports", async () => {
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockCompliantSG]
			});

			const result = await checkSecurityGroupAdminPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("sg-compliant");
		});

		it("should return NOTAPPLICABLE when no security groups exist", async () => {
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: []
			});

			const result = await checkSecurityGroupAdminPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No security groups found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for security groups with open SSH port", async () => {
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockNonCompliantSG]
			});

			const result = await checkSecurityGroupAdminPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("22");
		});

		it("should return FAIL for security groups with open RDP port", async () => {
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockMixedSG]
			});

			const result = await checkSecurityGroupAdminPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("3389");
		});

		it("should handle multiple violations in single security group", async () => {
			const multiViolationSG = {
				...mockNonCompliantSG,
				IpPermissions: [
					{
						FromPort: 22,
						ToPort: 3389,
						IpRanges: [{ CidrIp: "0.0.0.0/0" }]
					}
				]
			};

			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [multiViolationSG]
			});

			const result = await checkSecurityGroupAdminPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("22, 3389");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeSecurityGroupsCommand).rejects(new Error("API Error"));

			const result = await checkSecurityGroupAdminPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking security groups");
		});

		it("should handle security groups without GroupId", async () => {
			const invalidSG = { ...mockCompliantSG, GroupId: undefined };
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [invalidSG]
			});

			const result = await checkSecurityGroupAdminPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Security group found without ID");
		});
	});
});
