// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkSecurityGroupAuthorizedPorts from "./aws_security_group_authorized_ports";

const mockEC2Client = mockClient(EC2Client);

const mockCompliantSG = {
	GroupId: "sg-12345",
	GroupName: "compliant-sg",
	OwnerId: "123456789012",
	IpPermissions: [
		{
			IpProtocol: "tcp",
			FromPort: 80,
			ToPort: 80,
			IpRanges: [{ CidrIp: "0.0.0.0/0" }]
		},
		{
			IpProtocol: "tcp",
			FromPort: 443,
			ToPort: 443,
			IpRanges: [{ CidrIp: "0.0.0.0/0" }]
		}
	]
};

const mockNonCompliantSG = {
	GroupId: "sg-67890",
	GroupName: "non-compliant-sg",
	OwnerId: "123456789012",
	IpPermissions: [
		{
			IpProtocol: "tcp",
			FromPort: 22,
			ToPort: 22,
			IpRanges: [{ CidrIp: "0.0.0.0/0" }]
		}
	]
};

describe("checkSecurityGroupAuthorizedPorts", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for security groups with only authorized ports", async () => {
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockCompliantSG]
			});

			const result = await checkSecurityGroupAuthorizedPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-sg");
		});

		it("should return PASS for security groups with restricted CIDR", async () => {
			const sgWithRestrictedCIDR = {
				...mockCompliantSG,
				IpPermissions: [
					{
						IpProtocol: "tcp",
						FromPort: 22,
						ToPort: 22,
						IpRanges: [{ CidrIp: "10.0.0.0/8" }]
					}
				]
			};

			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [sgWithRestrictedCIDR]
			});

			const result = await checkSecurityGroupAuthorizedPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for security groups with unauthorized ports", async () => {
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [mockNonCompliantSG]
			});

			const result = await checkSecurityGroupAuthorizedPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("22");
		});

		it("should return FAIL for multiple unauthorized ports", async () => {
			const sgWithMultipleViolations = {
				...mockNonCompliantSG,
				IpPermissions: [
					{
						IpProtocol: "tcp",
						FromPort: 22,
						ToPort: 22,
						IpRanges: [{ CidrIp: "0.0.0.0/0" }]
					},
					{
						IpProtocol: "tcp",
						FromPort: 3389,
						ToPort: 3389,
						IpRanges: [{ CidrIp: "0.0.0.0/0" }]
					}
				]
			};

			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [sgWithMultipleViolations]
			});

			const result = await checkSecurityGroupAuthorizedPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("22, 3389");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no security groups exist", async () => {
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: []
			});

			const result = await checkSecurityGroupAuthorizedPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});

		it("should return ERROR when security group is missing required fields", async () => {
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [{ IpPermissions: [] }]
			});

			const result = await checkSecurityGroupAuthorizedPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		});

		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeSecurityGroupsCommand).rejects(new Error("API Error"));

			const result = await checkSecurityGroupAuthorizedPorts.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("API Error");
		});
	});
});
