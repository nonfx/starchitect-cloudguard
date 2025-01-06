// @ts-nocheck
import {
	ElasticBeanstalkClient,
	DescribeEnvironmentsCommand,
	DescribeConfigurationSettingsCommand
} from "@aws-sdk/client-elastic-beanstalk";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElasticBeanstalkAccessLogs from "./check-elastic-beanstalk-access-logs";

const mockElasticBeanstalkClient = mockClient(ElasticBeanstalkClient);

const mockEnvironment = {
	EnvironmentName: "test-env",
	EnvironmentId: "e-123456789",
	ApplicationName: "test-app"
};

describe("checkElasticBeanstalkAccessLogs", () => {
	beforeEach(() => {
		mockElasticBeanstalkClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when access logs are enabled for Classic ELB", async () => {
			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [mockEnvironment] });

			mockElasticBeanstalkClient.on(DescribeConfigurationSettingsCommand).resolves({
				ConfigurationSettings: [
					{
						OptionSettings: [
							{
								Namespace: "aws:elb:loadbalancer",
								OptionName: "AccessLogsS3Enabled",
								Value: "true"
							}
						]
					}
				]
			});

			const result = await checkElasticBeanstalkAccessLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-env");
		});

		it("should return PASS when access logs are enabled for ALB", async () => {
			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [mockEnvironment] });

			mockElasticBeanstalkClient.on(DescribeConfigurationSettingsCommand).resolves({
				ConfigurationSettings: [
					{
						OptionSettings: [
							{
								Namespace: "aws:elbv2:loadbalancer",
								OptionName: "AccessLogsS3Enabled",
								Value: "true"
							}
						]
					}
				]
			});

			const result = await checkElasticBeanstalkAccessLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when environment does not use load balancing", async () => {
			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [mockEnvironment] });

			mockElasticBeanstalkClient.on(DescribeConfigurationSettingsCommand).resolves({
				ConfigurationSettings: [
					{
						OptionSettings: []
					}
				]
			});

			const result = await checkElasticBeanstalkAccessLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("Environment does not use load balancing");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when access logs are disabled", async () => {
			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [mockEnvironment] });

			mockElasticBeanstalkClient.on(DescribeConfigurationSettingsCommand).resolves({
				ConfigurationSettings: [
					{
						OptionSettings: [
							{
								Namespace: "aws:elb:loadbalancer",
								OptionName: "AccessLogsS3Enabled",
								Value: "false"
							}
						]
					}
				]
			});

			const result = await checkElasticBeanstalkAccessLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Access logs are not enabled for the load balancer");
		});

		it("should handle multiple environments with mixed compliance", async () => {
			const secondEnv = {
				...mockEnvironment,
				EnvironmentName: "test-env-2",
				EnvironmentId: "e-987654321"
			};

			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [mockEnvironment, secondEnv] });

			mockElasticBeanstalkClient
				.on(DescribeConfigurationSettingsCommand)
				.resolves({
					ConfigurationSettings: [
						{
							OptionSettings: [
								{
									Namespace: "aws:elb:loadbalancer",
									OptionName: "AccessLogsS3Enabled",
									Value: "true"
								}
							]
						}
					]
				})
				.on(DescribeConfigurationSettingsCommand, { EnvironmentName: "test-env-2" })
				.resolves({
					ConfigurationSettings: [
						{
							OptionSettings: [
								{
									Namespace: "aws:elb:loadbalancer",
									OptionName: "AccessLogsS3Enabled",
									Value: "false"
								}
							]
						}
					]
				});

			const result = await checkElasticBeanstalkAccessLogs.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no environments exist", async () => {
			mockElasticBeanstalkClient.on(DescribeEnvironmentsCommand).resolves({ Environments: [] });

			const result = await checkElasticBeanstalkAccessLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe(
				"No Elastic Beanstalk environments found in the region"
			);
		});

		it("should return ERROR when API call fails", async () => {
			mockElasticBeanstalkClient.on(DescribeEnvironmentsCommand).rejects(new Error("API Error"));

			const result = await checkElasticBeanstalkAccessLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Elastic Beanstalk environments");
		});

		it("should return ERROR when configuration settings cannot be retrieved", async () => {
			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [mockEnvironment] });

			mockElasticBeanstalkClient
				.on(DescribeConfigurationSettingsCommand)
				.resolves({ ConfigurationSettings: [] });

			const result = await checkElasticBeanstalkAccessLogs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to retrieve configuration settings");
		});
	});
});
