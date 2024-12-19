import { AutoScalingClient, DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkAutoScalingMultipleInstanceTypes from "./aws_autoscaling_multiple_instance_types";

const mockAutoScalingClient = mockClient(AutoScalingClient);

const mockCompliantASG = {
    AutoScalingGroupName: "compliant-asg",
    AutoScalingGroupARN: "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:compliant-asg",
    AvailabilityZones: ["us-east-1a", "us-east-1b"],
    MixedInstancesPolicy: {
        LaunchTemplate: {
            Overrides: [
                { InstanceType: "t3.micro" },
                { InstanceType: "t3.small" }
            ]
        }
    }
};

const mockNonCompliantASG = {
    AutoScalingGroupName: "non-compliant-asg",
    AutoScalingGroupARN: "arn:aws:autoscaling:us-east-1:123456789012:autoScalingGroup:non-compliant-asg",
    AvailabilityZones: ["us-east-1a"],
    MixedInstancesPolicy: {
        LaunchTemplate: {
            Overrides: [
                { InstanceType: "t3.micro" }
            ]
        }
    }
};

describe("checkAutoScalingMultipleInstanceTypes", () => {
    beforeEach(() => {
        mockAutoScalingClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for ASG with multiple instance types and AZs", async () => {
            mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
                AutoScalingGroups: [mockCompliantASG]
            });

            const result = await checkAutoScalingMultipleInstanceTypes("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("compliant-asg");
            expect(result.checks[0].resourceArn).toBe(mockCompliantASG.AutoScalingGroupARN);
        });

        it("should return NOTAPPLICABLE when no ASGs exist", async () => {
            mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
                AutoScalingGroups: []
            });

            const result = await checkAutoScalingMultipleInstanceTypes("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No Auto Scaling groups found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for ASG with single instance type", async () => {
            mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
                AutoScalingGroups: [mockNonCompliantASG]
            });

            const result = await checkAutoScalingMultipleInstanceTypes("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("does not use multiple instance types");
        });

        it("should return FAIL for ASG with single AZ", async () => {
            mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
                AutoScalingGroups: [{
                    ...mockCompliantASG,
                    AvailabilityZones: ["us-east-1a"]
                }]
            });

            const result = await checkAutoScalingMultipleInstanceTypes("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("does not use multiple Availability Zones");
        });

        it("should return FAIL for ASG without MixedInstancesPolicy", async () => {
            mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
                AutoScalingGroups: [{
                    ...mockCompliantASG,
                    MixedInstancesPolicy: undefined
                }]
            });

            const result = await checkAutoScalingMultipleInstanceTypes("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).rejects(
                new Error("API Error")
            );

            const result = await checkAutoScalingMultipleInstanceTypes("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking Auto Scaling groups");
        });

        it("should return ERROR for ASG without name or ARN", async () => {
            mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
                AutoScalingGroups: [{ 
                    AvailabilityZones: ["us-east-1a"]
                }]
            });

            const result = await checkAutoScalingMultipleInstanceTypes("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Auto Scaling group found without name or ARN");
        });
    });

    describe("Mixed Scenarios", () => {
        it("should handle multiple ASGs with different configurations", async () => {
            mockAutoScalingClient.on(DescribeAutoScalingGroupsCommand).resolves({
                AutoScalingGroups: [mockCompliantASG, mockNonCompliantASG]
            });

            const result = await checkAutoScalingMultipleInstanceTypes("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });
});