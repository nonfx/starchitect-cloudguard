// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	EC2Client,
	DescribeInstancesCommand,
	DescribeSecurityGroupsCommand
} from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDefaultSecurityGroupUsage from "./aws_ec2_default_security_group";

const mockEC2Client = mockClient(EC2Client);

const mockInstance1 = {
	InstanceId: "i-1234567890abcdef0",
	SecurityGroups: [{ GroupId: "sg-custom", GroupName: "custom-sg" }]
};

const mockInstance2 = {
	InstanceId: "i-0987654321fedcba0",
	SecurityGroups: [{ GroupId: "sg-default", GroupName: "default" }]
};

const mockSecurityGroups = [
	{
		GroupId: "sg-default",
		GroupName: "default",
		IpPermissions: [],
		IpPermissionsEgress: []
	},
	{
		GroupId: "sg-custom",
		GroupName: "custom-sg",
		IpPermissions: [],
		IpPermissionsEgress: []
	}
];

describe("checkDefaultSecurityGroupUsage", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for instances using custom security groups", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [{ Instances: [mockInstance1] }]
			});
			mockEC2Client
				.on(DescribeSecurityGroupsCommand)
				.resolves({ SecurityGroups: mockSecurityGroups });

			const result = await checkDefaultSecurityGroupUsage.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockInstance1.InstanceId);
		});

		it("should return PASS for default security group with no rules", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [{ Instances: [mockInstance1] }]
			});
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [
					{
						GroupId: "sg-default",
						GroupName: "default",
						IpPermissions: [],
						IpPermissionsEgress: []
					}
				]
			});

			const result = await checkDefaultSecurityGroupUsage.execute("us-east-1");
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for instances using default security group", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [{ Instances: [mockInstance2] }]
			});
			mockEC2Client
				.on(DescribeSecurityGroupsCommand)
				.resolves({ SecurityGroups: mockSecurityGroups });

			const result = await checkDefaultSecurityGroupUsage.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("using default security group");
		});

		it("should return FAIL for default security group with active rules", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [{ Instances: [mockInstance1] }]
			});
			mockEC2Client.on(DescribeSecurityGroupsCommand).resolves({
				SecurityGroups: [
					{
						GroupId: "sg-default",
						GroupName: "default",
						IpPermissions: [{ FromPort: 22, ToPort: 22, IpProtocol: "tcp" }],
						IpPermissionsEgress: []
					}
				]
			});

			const result = await checkDefaultSecurityGroupUsage.execute("us-east-1");
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].message).toContain("active rules configured");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({ Reservations: [] });

			const result = await checkDefaultSecurityGroupUsage.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		});

		it("should return ERROR when API calls fail", async () => {
			mockEC2Client.on(DescribeInstancesCommand).rejects(new Error("API Error"));

			const result = await checkDefaultSecurityGroupUsage.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking security groups");
		});

		it("should handle instances without security groups", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [
							{
								InstanceId: "i-test",
								SecurityGroups: []
							}
						]
					}
				]
			});
			mockEC2Client
				.on(DescribeSecurityGroupsCommand)
				.resolves({ SecurityGroups: mockSecurityGroups });

			const result = await checkDefaultSecurityGroupUsage.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});
});
