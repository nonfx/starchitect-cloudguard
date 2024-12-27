// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkEc2DetailedMonitoring from "./aws_ec2_detailed_monitoring";

const mockEC2Client = mockClient(EC2Client);

const mockInstance = (id: string, monitoringState: string, ownerId: string = "123456789012") => ({
	InstanceId: id,
	OwnerId: ownerId,
	Monitoring: { State: monitoringState },
	State: { Name: "running" }
});

describe("checkEc2DetailedMonitoring", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when detailed monitoring is enabled", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockInstance("i-1234567890", "enabled")]
					}
				]
			});

			const result = await checkEc2DetailedMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("i-1234567890");
			expect(result.checks[0].resourceArn).toBe(
				"arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890"
			);
		});

		it("should return NOTAPPLICABLE when no instances exist", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: []
			});

			const result = await checkEc2DetailedMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No running EC2 instances found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when detailed monitoring is disabled", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockInstance("i-1234567890", "disabled")]
					}
				]
			});

			const result = await checkEc2DetailedMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Detailed monitoring is not enabled for this EC2 instance"
			);
		});

		it("should handle multiple instances with mixed monitoring states", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [
							mockInstance("i-1234567890", "enabled"),
							mockInstance("i-0987654321", "disabled")
						]
					}
				]
			});

			const result = await checkEc2DetailedMonitoring.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle instance without InstanceId", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [{ Monitoring: { State: "enabled" } }]
					}
				]
			});

			const result = await checkEc2DetailedMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Instance found without ID");
		});
	});

	describe("Pagination and Error Handling", () => {
		it("should handle pagination correctly", async () => {
			mockEC2Client
				.on(DescribeInstancesCommand)
				.resolvesOnce({
					Reservations: [
						{
							Instances: [mockInstance("i-1234567890", "enabled")]
						}
					],
					NextToken: "token1"
				})
				.resolvesOnce({
					Reservations: [
						{
							Instances: [mockInstance("i-0987654321", "disabled")]
						}
					]
				});

			const result = await checkEc2DetailedMonitoring.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});

		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeInstancesCommand).rejects(new Error("API Error"));

			const result = await checkEc2DetailedMonitoring.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking EC2 instances: API Error");
		});
	});
});
