import {
	ElasticBeanstalkClient,
	DescribeConfigurationSettingsCommand
} from "@aws-sdk/client-elastic-beanstalk";
import { getAllBeanstalkEnvironments } from "../../utils/aws/get-all-elastic-beanstalk-environments.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElasticBeanstalkHttpsCompliance(
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

		// Check each environment for HTTPS configuration
		for (const env of environments) {
			if (!env.EnvironmentName || !env.EnvironmentId) {
				results.checks.push({
					resourceName: "Unknown Environment",
					status: ComplianceStatus.ERROR,
					message: "Environment found without name or ID"
				});
				continue;
			}

			try {
				const configSettings = await client.send(
					new DescribeConfigurationSettingsCommand({
						ApplicationName: env.ApplicationName,
						EnvironmentName: env.EnvironmentName
					})
				);

				let hasHttpsListener = false;

				// Check configuration settings for HTTPS listener
				if (configSettings.ConfigurationSettings) {
					for (const config of configSettings.ConfigurationSettings) {
						const httpsSettings = config.OptionSettings?.find(
							setting =>
								setting.Namespace === "aws:elb:listener:443" &&
								setting.OptionName === "ListenerProtocol" &&
								setting.Value === "HTTPS"
						);

						if (httpsSettings) {
							hasHttpsListener = true;
							break;
						}
					}
				}

				results.checks.push({
					resourceName: env.EnvironmentName,
					resourceArn: env.EnvironmentArn,
					status: hasHttpsListener ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasHttpsListener ? undefined : "HTTPS is not enabled on the load balancer"
				});
			} catch (error) {
				results.checks.push({
					resourceName: env.EnvironmentName,
					resourceArn: env.EnvironmentArn,
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
	const results = await checkElasticBeanstalkHttpsCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure that HTTPS is enabled on load balancer",
	description:
		"The simplest way to use HTTPS with an Elastic Beanstalk environment is to assign a server certificate to your environment's load balancer. When you configure your load balancer to terminate HTTPS, the connection between the client and the load balancer is secure.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_6.4",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkElasticBeanstalkHttpsCompliance,
	serviceName: "AWS Elastic Beanstalk",
	shortServiceName: "elastic-beanstalk"
} satisfies RuntimeTest;
