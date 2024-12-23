import { AutoScalingClient, DescribeLaunchConfigurationsCommand } from "@aws-sdk/client-auto-scaling";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkAutoScalingPublicIp from "./aws_autoscaling_no_public_ip";

const mockAutoScalingClient = mockClient(AutoScalingClient);

const mockLaunchConfigWithPublicIP = {
    LaunchConfigurationName: "test-config-1",
    LaunchConfigurationARN: "arn:aws:autoscaling:us-east-1:123456789012:launchConfiguration:test-config-1",
    AssociatePublicIpAddress: true
};

const mockLaunchConfigWithoutPublicIP = {
    LaunchConfigurationName: "test-config-2",
    LaunchConfigurationARN: "arn:aws:autoscaling:us-east-1:123456789012:launchConfiguration:test-config-2",
    AssociatePublicIpAddress: false
};

describe("checkAutoScalingPublicIp", () => {
    beforeEach(() => {
        mockAutoScalingClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when launch configuration does not assign public IPs", async () => {
            mockAutoScalingClient.on(DescribeLaunchConfigurationsCommand).resolves({
                LaunchConfigurations: [mockLaunchConfigWithoutPublicIP]
            });

            const result = await checkAutoScalingPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("test-config-2");
            expect(result.checks[0].resourceArn).toBe(mockLaunchConfigWithoutPublicIP.LaunchConfigurationARN);
        });

        it("should return NOTAPPLICABLE when no launch configurations exist", async () => {
            mockAutoScalingClient.on(DescribeLaunchConfigurationsCommand).resolves({
                LaunchConfigurations: []
            });

            const result = await checkAutoScalingPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No Auto Scaling launch configurations found");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when launch configuration assigns public IPs", async () => {
            mockAutoScalingClient.on(DescribeLaunchConfigurationsCommand).resolves({
                LaunchConfigurations: [mockLaunchConfigWithPublicIP]
            });

            const result = await checkAutoScalingPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Launch configuration assigns public IP addresses to instances");
        });

        it("should handle mixed configurations", async () => {
            mockAutoScalingClient.on(DescribeLaunchConfigurationsCommand).resolves({
                LaunchConfigurations: [mockLaunchConfigWithPublicIP, mockLaunchConfigWithoutPublicIP]
            });

            const result = await checkAutoScalingPublicIp("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
        });

        it("should handle launch configurations without names", async () => {
            mockAutoScalingClient.on(DescribeLaunchConfigurationsCommand).resolves({
                LaunchConfigurations: [{ AssociatePublicIpAddress: true }]
            });

            const result = await checkAutoScalingPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Launch configuration found without name");
        });
    });

    describe("Pagination and Error Handling", () => {
        it("should handle pagination correctly", async () => {
            mockAutoScalingClient
                .on(DescribeLaunchConfigurationsCommand)
                .resolvesOnce({
                    LaunchConfigurations: [mockLaunchConfigWithPublicIP],
                    NextToken: "token1"
                })
                .resolvesOnce({
                    LaunchConfigurations: [mockLaunchConfigWithoutPublicIP]
                });

            const result = await checkAutoScalingPublicIp("us-east-1");
            expect(result.checks).toHaveLength(2);
        });

        it("should return ERROR when API call fails", async () => {
            mockAutoScalingClient
                .on(DescribeLaunchConfigurationsCommand)
                .rejects(new Error("API Error"));

            const result = await checkAutoScalingPublicIp("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Error checking launch configurations: API Error");
        });
    });
});