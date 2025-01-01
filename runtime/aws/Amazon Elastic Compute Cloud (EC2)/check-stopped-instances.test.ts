// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkStoppedInstances from "./check-stopped-instances";

const mockEC2Client = mockClient(EC2Client);

const generateStopTime = (daysAgo: number) => {
	const date = new Date();
	date.setDate(date.getDate() - daysAgo);
	return date.toISOString();
};

describe("checkStoppedInstances", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for instances stopped less than 90 days", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [
							{
								InstanceId: "i-123456789",
								StateTransitionReason: `User initiated (${generateStopTime(45)})`
							}
						]
					}
				]
			});

			const result = await checkStoppedInstances.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("i-123456789");
		});

		it("should return NOTAPPLICABLE when no stopped instances found", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: []
			});

			const result = await checkStoppedInstances.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No stopped EC2 instances found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for instances stopped more than 90 days", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [
							{
								InstanceId: "i-987654321",
								StateTransitionReason: `User initiated (${generateStopTime(100)})`
							}
						]
					}
				]
			});

			const result = await checkStoppedInstances.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Instance has been stopped for 100 days (maximum allowed: 90 days)"
			);
		});

		it("should handle multiple instances with mixed compliance", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [
							{
								InstanceId: "i-compliant",
								StateTransitionReason: `User initiated (${generateStopTime(45)})`
							},
							{
								InstanceId: "i-noncompliant",
								StateTransitionReason: `User initiated (${generateStopTime(120)})`
							}
						]
					}
				]
			});

			const result = await checkStoppedInstances.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeInstancesCommand).rejects(new Error("API Error"));

			const result = await checkStoppedInstances.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking EC2 instances");
		});

		it("should handle instances with missing information", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [
							{
								InstanceId: "i-incomplete"
							}
						]
					}
				]
			});

			const result = await checkStoppedInstances.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Instance missing state transition information");
		});

		it("should handle invalid state transition reason format", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [
							{
								InstanceId: "i-invalid",
								StateTransitionReason: "Invalid format"
							}
						]
					}
				]
			});

			const result = await checkStoppedInstances.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to determine instance stop time");
		});
	});

	describe("Pagination", () => {
		it("should handle paginated results", async () => {
			mockEC2Client
				.on(DescribeInstancesCommand)
				.resolvesOnce({
					Reservations: [
						{
							Instances: [
								{
									InstanceId: "i-page1",
									StateTransitionReason: `User initiated (${generateStopTime(45)})`
								}
							]
						}
					],
					NextToken: "token1"
				})
				.resolvesOnce({
					Reservations: [
						{
							Instances: [
								{
									InstanceId: "i-page2",
									StateTransitionReason: `User initiated (${generateStopTime(100)})`
								}
							]
						}
					]
				});

			const result = await checkStoppedInstances.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
