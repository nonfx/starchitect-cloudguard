// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkAutoScalingLaunchTemplate from "./aws_autoscaling_launch_template";

const mockAutoScalingClient = mockClient(AutoScalingClient);

const mockASGWithLaunchTemplate = {
	AutoScalingGroupName: "test-asg-1",
	AutoScalingGroupARN: "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:test-asg-1",
	LaunchTemplate: {
		LaunchTemplateId: "lt-1234567890",
		Version: "1"
	}
};

const mockASGWithMixedInstances = {
	AutoScalingGroupName: "test-asg-2",
	AutoScalingGroupARN: "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:test-asg-2",
	MixedInstancesPolicy: {
		LaunchTemplate: {
			LaunchTemplateSpecification: {
				LaunchTemplateId: "lt-0987654321",
				Version: "1"
			}
		}
	}
};

const mockASGWithLaunchConfig = {
	AutoScalingGroupName: "test-asg-3",
	AutoScalingGroupARN: "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:test-asg-3",
	LaunchConfigurationName: "test-launch-config"
};

describe("checkAutoScalingLaunchTemplate", () => {
	beforeEach(() => {
		mockAutoScalingClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when ASG uses launch template", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
				AutoScalingGroups: [mockASGWithLaunchTemplate]
			});

			const result = await checkAutoScalingLaunchTemplate.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-asg-1");
		});

		it("should return PASS when ASG uses mixed instances policy with launch template", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
				AutoScalingGroups: [mockASGWithMixedInstances]
			});

			const result = await checkAutoScalingLaunchTemplate.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-asg-2");
		});

		it("should return NOTAPPLICABLE when no ASGs exist", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
				AutoScalingGroups: []
			});

			const result = await checkAutoScalingLaunchTemplate.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Auto Scaling groups found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when ASG uses launch configuration", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
				AutoScalingGroups: [mockASGWithLaunchConfig]
			});

			const result = await checkAutoScalingLaunchTemplate.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Auto Scaling group must use launch template instead of launch configuration"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
				AutoScalingGroups: [
					mockASGWithLaunchTemplate,
					mockASGWithLaunchConfig,
					mockASGWithMixedInstances
				]
			});

			const result = await checkAutoScalingLaunchTemplate.execute("us-east-1");
			expect(result.checks).toHaveLength(3);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[2].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).rejects(new Error("API Error"));

			const result = await checkAutoScalingLaunchTemplate.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking Auto Scaling groups: API Error");
		});

		it("should handle ASG without name", async () => {
			mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
				AutoScalingGroups: [{ AutoScalingGroupARN: "arn:aws:..." }]
			});

			const result = await checkAutoScalingLaunchTemplate.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Auto Scaling group found without name");
		});
	});
});
