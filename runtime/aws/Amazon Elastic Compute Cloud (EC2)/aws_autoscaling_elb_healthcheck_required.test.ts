// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAutoScalingELBHealthCheck from "./aws_autoscaling_elb_healthcheck_required";

const mockAutoScalingClient = mockClient(AutoScalingClient);

const mockASGWithELBHealthCheck = {
	AutoScalingGroupName: "test-asg-1",
	AutoScalingGroupARN: "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:test-asg-1",
	LoadBalancerNames: ["test-lb"],
	TargetGroupARNs: [
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test-tg/1234567890"
	],
	HealthCheckType: "ELB"
};

const mockASGWithoutELBHealthCheck = {
	AutoScalingGroupName: "test-asg-2",
	AutoScalingGroupARN: "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:test-asg-2",
	LoadBalancerNames: [],
	TargetGroupARNs: [],
	HealthCheckType: "EC2"
};

describe("checkAutoScalingELBHealthCheck", () => {
	beforeEach(() => {
		mockAutoScalingClient.reset();
	});

	it("should return PASS when ASG uses ELB health check", async () => {
		mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
			AutoScalingGroups: [mockASGWithELBHealthCheck]
		});

		const result = await checkAutoScalingELBHealthCheck.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		expect(result.checks[0].resourceName).toBe("test-asg-1");
		expect(result.checks[0].resourceArn).toBe(mockASGWithELBHealthCheck.AutoScalingGroupARN);
	});

	it("should return PASS when ASG has no load balancer", async () => {
		mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
			AutoScalingGroups: [mockASGWithoutELBHealthCheck]
		});

		const result = await checkAutoScalingELBHealthCheck.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		expect(result.checks[0].message).toBe("Auto Scaling group has no load balancer attached");
	});

	it("should return NOTAPPLICABLE when no ASGs exist", async () => {
		mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
			AutoScalingGroups: []
		});

		const result = await checkAutoScalingELBHealthCheck.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
	});

	it("should return ERROR when API call fails", async () => {
		mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).rejects(new Error("API Error"));

		const result = await checkAutoScalingELBHealthCheck.execute("us-east-1");
		expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		expect(result.checks[0].message).toBe("Error checking Auto Scaling groups: API Error");
	});

	it("should handle pagination", async () => {
		mockAutoScalingClient
			.on(DescribeAutoScalingGroupsCommand)
			.resolvesOnce({
				AutoScalingGroups: [mockASGWithELBHealthCheck],
				NextToken: "token1"
			})
			.resolvesOnce({
				AutoScalingGroups: [mockASGWithoutELBHealthCheck]
			});

		const result = await checkAutoScalingELBHealthCheck.execute("us-east-1");
		expect(result.checks).toHaveLength(2);
	});
});
