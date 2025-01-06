// @ts-nocheck
import {
	ElasticBeanstalkClient,
	DescribeEnvironmentsCommand,
	DescribeConfigurationSettingsCommand
} from "@aws-sdk/client-elastic-beanstalk";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkElasticBeanstalkHealth from "./check-elastic-beanstalk-health";

const mockElasticBeanstalkClient = mockClient(ElasticBeanstalkClient);

const mockEnvironment = {
	EnvironmentName: "test-env",
	EnvironmentId: "e-123456789",
	ApplicationName: "test-app",
	EnvironmentArn: "arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/test-app/test-env"
};

describe("checkElasticBeanstalkHealth", () => {
	beforeEach(() => {
		mockElasticBeanstalkClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when enhanced health reporting is enabled", async () => {
			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [mockEnvironment] });

			mockElasticBeanstalkClient.on(DescribeConfigurationSettingsCommand).resolves({
				ConfigurationSettings: [
					{
						OptionSettings: [
							{
								Namespace: "aws:elasticbeanstalk:healthreporting:system",
								OptionName: "SystemType",
								Value: "enhanced"
							}
						]
					}
				]
			});

			const result = await checkElasticBeanstalkHealth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-env");
		});

		it("should return NOTAPPLICABLE when no environments exist", async () => {
			mockElasticBeanstalkClient.on(DescribeEnvironmentsCommand).resolves({ Environments: [] });

			const result = await checkElasticBeanstalkHealth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe(
				"No Elastic Beanstalk environments found in the region"
			);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when enhanced health reporting is disabled", async () => {
			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [mockEnvironment] });

			mockElasticBeanstalkClient.on(DescribeConfigurationSettingsCommand).resolves({
				ConfigurationSettings: [
					{
						OptionSettings: [
							{
								Namespace: "aws:elasticbeanstalk:healthreporting:system",
								OptionName: "SystemType",
								Value: "basic"
							}
						]
					}
				]
			});

			const result = await checkElasticBeanstalkHealth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Enhanced health reporting is not enabled");
		});

		it("should handle multiple environments with mixed compliance", async () => {
			const secondEnvironment = { ...mockEnvironment, EnvironmentName: "test-env-2" };

			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [mockEnvironment, secondEnvironment] });

			mockElasticBeanstalkClient
				.on(DescribeConfigurationSettingsCommand)
				.resolves({
					ConfigurationSettings: [
						{
							OptionSettings: [
								{
									Namespace: "aws:elasticbeanstalk:healthreporting:system",
									OptionName: "SystemType",
									Value: "enhanced"
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
									Namespace: "aws:elasticbeanstalk:healthreporting:system",
									OptionName: "SystemType",
									Value: "basic"
								}
							]
						}
					]
				});

			const result = await checkElasticBeanstalkHealth.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when DescribeEnvironments fails", async () => {
			mockElasticBeanstalkClient.on(DescribeEnvironmentsCommand).rejects(new Error("API Error"));

			const result = await checkElasticBeanstalkHealth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Elastic Beanstalk environments");
		});

		it("should return ERROR when DescribeConfigurationSettings fails", async () => {
			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [mockEnvironment] });

			mockElasticBeanstalkClient
				.on(DescribeConfigurationSettingsCommand)
				.rejects(new Error("Configuration Error"));

			const result = await checkElasticBeanstalkHealth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking configuration");
		});

		it("should handle environments without name or ID", async () => {
			mockElasticBeanstalkClient
				.on(DescribeEnvironmentsCommand)
				.resolves({ Environments: [{ ApplicationName: "test-app" }] });

			const result = await checkElasticBeanstalkHealth.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Environment found without name or ID");
		});
	});
});
