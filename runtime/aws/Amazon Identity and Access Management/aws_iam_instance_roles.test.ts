import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkIamInstanceRoles from "./aws_iam_instance_roles";

const mockEC2Client = mockClient(EC2Client);

const mockInstanceWithRole = {
	InstanceId: "i-1234567890abcdef0",
	IamInstanceProfile: {
		Arn: "arn:aws:iam::123456789012:instance-profile/test-role",
		Id: "AIPAXXX"
	},
	State: { Name: "running" }
};

const mockInstanceWithoutRole = {
	InstanceId: "i-0987654321fedcba0",
	State: { Name: "running" }
};

describe("checkIamInstanceRoles", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all instances have IAM roles", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockInstanceWithRole]
					}
				]
			});

			const result = await checkIamInstanceRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockInstanceWithRole.InstanceId);
			expect(result.checks[0].resourceArn).toBe(mockInstanceWithRole.IamInstanceProfile.Arn);
		});

		it("should handle pagination correctly for compliant instances", async () => {
			mockEC2Client
				.on(DescribeInstancesCommand)
				.resolvesOnce({
					Reservations: [{ Instances: [mockInstanceWithRole] }],
					NextToken: "token1"
				})
				.resolvesOnce({
					Reservations: [{ Instances: [mockInstanceWithRole] }]
				});

			const result = await checkIamInstanceRoles.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when instances don't have IAM roles", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockInstanceWithoutRole]
					}
				]
			});

			const result = await checkIamInstanceRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("EC2 instance does not have an IAM role attached");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockInstanceWithRole, mockInstanceWithoutRole]
					}
				]
			});

			const result = await checkIamInstanceRoles.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases and Error Handling", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: []
			});

			const result = await checkIamInstanceRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No running EC2 instances found in the region");
		});

		it("should handle instances without InstanceId", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [{ State: { Name: "running" } }]
					}
				]
			});

			const result = await checkIamInstanceRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Instance found without Instance ID");
		});

		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeInstancesCommand).rejects(new Error("API call failed"));

			const result = await checkIamInstanceRoles.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking EC2 instances");
		});
	});
});
