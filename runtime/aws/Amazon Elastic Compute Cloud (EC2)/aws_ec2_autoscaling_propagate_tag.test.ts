// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAutoScalingTagPropagation from "./aws_ec2_autoscaling_propagate_tag";

const mockAutoScalingClient = mockClient(AutoScalingClient);

const mockASGWithPropagatingTags = {
	AutoScalingGroupName: "test-asg-1",
	AutoScalingGroupARN: "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:test-asg-1",
	Tags: [
		{ Key: "Environment", Value: "Production", PropagateAtLaunch: true },
		{ Key: "Project", Value: "MainApp", PropagateAtLaunch: true }
	]
};

const mockASGWithNonPropagatingTags = {
	AutoScalingGroupName: "test-asg-2",
	AutoScalingGroupARN: "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:test-asg-2",
	Tags: [
		{ Key: "Environment", Value: "Production", PropagateAtLaunch: true },
		{ Key: "Project", Value: "MainApp", PropagateAtLaunch: false }
	]
};

describe("checkAutoScalingTagPropagation", () => {
	beforeEach(() => {
		mockAutoScalingClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all tags are set to propagate", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
				AutoScalingGroups: [mockASGWithPropagatingTags]
			});

			const result = await checkAutoScalingTagPropagation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-asg-1");
			expect(result.checks[0].message).toBeUndefined();
		});

		it("should return NOTAPPLICABLE when no ASGs exist", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
				AutoScalingGroups: []
			});

			const result = await checkAutoScalingTagPropagation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Auto Scaling Groups found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when some tags are not set to propagate", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
				AutoScalingGroups: [mockASGWithNonPropagatingTags]
			});

			const result = await checkAutoScalingTagPropagation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("1 tags are not set to propagate to EC2 instances");
		});

		it("should handle ASGs without name or ARN", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
				AutoScalingGroups: [{ Tags: [] }]
			});

			const result = await checkAutoScalingTagPropagation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Auto Scaling Group found without name or ARN");
		});
	});

	describe("Pagination and Error Handling", () => {
		it("should handle pagination correctly", async () => {
			mockAutoScalingClient
				.on(DescribeAutoScalingGroupsCommand)
				.resolvesOnce({
					AutoScalingGroups: [mockASGWithPropagatingTags],
					NextToken: "token1"
				})
				.resolvesOnce({
					AutoScalingGroups: [mockASGWithNonPropagatingTags]
				});

			const result = await checkAutoScalingTagPropagation.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should return ERROR when API call fails", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).rejects(new Error("API Error"));

			const result = await checkAutoScalingTagPropagation.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking Auto Scaling Groups: API Error");
		});
	});
});
