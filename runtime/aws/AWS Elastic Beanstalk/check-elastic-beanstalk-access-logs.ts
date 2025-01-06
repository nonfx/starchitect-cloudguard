import {
	ElasticBeanstalkClient,
	DescribeConfigurationSettingsCommand
} from "@aws-sdk/client-elastic-beanstalk";
import { getAllBeanstalkEnvironments } from "./get-all-elastic-beanstalk-environments.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElasticBeanstalkAccessLogs(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ElasticBeanstalkClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Elastic Beanstalk environments using pagination
		const environments = (await getAllBeanstalkEnvironments(client)) ?? [];

		if (environments.length === 0) {
			results.checks = [
				{
					resourceName: "No Elastic Beanstalk Environments",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Elastic Beanstalk environments found in the region"
				}
			];
			return results;
		}

		for (const env of environments) {
			if (!env.EnvironmentName || !env.EnvironmentId) {
				continue;
			}

			try {
				const configSettings = await client.send(
					new DescribeConfigurationSettingsCommand({
						ApplicationName: env.ApplicationName,
						EnvironmentName: env.EnvironmentName
					})
				);

				const settings = configSettings.ConfigurationSettings?.[0]?.OptionSettings;
				if (!settings) {
					results.checks.push({
						resourceName: env.EnvironmentName,
						status: ComplianceStatus.ERROR,
						message: "Unable to retrieve configuration settings"
					});
					continue;
				}

				// Check for load balancer type and access logs configuration
				const usesClassicLB = settings.some(s => s.Namespace === "aws:elb:loadbalancer");
				const usesALB = settings.some(s => s.Namespace === "aws:elbv2:loadbalancer");

				if (!usesClassicLB && !usesALB) {
					results.checks.push({
						resourceName: env.EnvironmentName,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "Environment does not use load balancing"
					});
					continue;
				}

				const accessLogsEnabled = settings.some(
					s =>
						(s.Namespace === "aws:elb:loadbalancer" || s.Namespace === "aws:elbv2:loadbalancer") &&
						s.OptionName === "AccessLogsS3Enabled" &&
						s.Value === "true"
				);

				results.checks.push({
					resourceName: env.EnvironmentName,
					resourceArn: `arn:aws:elasticbeanstalk:${region}:${env.EnvironmentId}`,
					status: accessLogsEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: accessLogsEnabled
						? undefined
						: "Access logs are not enabled for the load balancer"
				});
			} catch (error) {
				results.checks.push({
					resourceName: env.EnvironmentName,
					status: ComplianceStatus.ERROR,
					message: `Error checking environment configuration: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Elastic Beanstalk environments: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElasticBeanstalkAccessLogs(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure access logs are enabled",
	description:
		"When you enable load balancing, your AWS Elastic Beanstalk environment is equipped with an Elastic Load Balancing load balancer to distribute traffic among the instances in your environment",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_6.3",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkElasticBeanstalkAccessLogs,
	serviceName: "AWS Elastic Beanstalk",
	shortServiceName: "elastic-beanstalk"
} satisfies RuntimeTest;
