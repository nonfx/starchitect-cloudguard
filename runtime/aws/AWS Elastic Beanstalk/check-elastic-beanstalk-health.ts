import {
	ElasticBeanstalkClient,
	DescribeConfigurationSettingsCommand
} from "@aws-sdk/client-elastic-beanstalk";
import { getAllBeanstalkEnvironments } from "./get-all-elastic-beanstalk-environments.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEnhancedHealthReporting(
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
					resourceName: "No Environments",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Elastic Beanstalk environments found in the region"
				}
			];
			return results;
		}

		// Check each environment's configuration
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
						EnvironmentName: env.EnvironmentName,
						ApplicationName: env.ApplicationName
					})
				);

				let hasEnhancedHealth = false;

				// Look for enhanced health reporting setting
				if (configSettings.ConfigurationSettings) {
					for (const config of configSettings.ConfigurationSettings) {
						const healthSetting = config.OptionSettings?.find(
							setting =>
								setting.Namespace === "aws:elasticbeanstalk:healthreporting:system" &&
								setting.OptionName === "SystemType"
						);

						if (healthSetting?.Value === "enhanced") {
							hasEnhancedHealth = true;
							break;
						}
					}
				}

				results.checks.push({
					resourceName: env.EnvironmentName,
					resourceArn: env.EnvironmentArn,
					status: hasEnhancedHealth ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasEnhancedHealth ? undefined : "Enhanced health reporting is not enabled"
				});
			} catch (error) {
				results.checks.push({
					resourceName: env.EnvironmentName,
					resourceArn: env.EnvironmentArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking configuration: ${error instanceof Error ? error.message : String(error)}`
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
	const results = await checkEnhancedHealthReporting(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Elastic Beanstalk environments should have enhanced health reporting enabled",
	description:
		"Elastic Beanstalk environments must enable enhanced health reporting for better infrastructure monitoring and rapid response to health changes.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ElasticBeanstalk.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkEnhancedHealthReporting,
	serviceName: "AWS Elastic Beanstalk",
	shortServiceName: "elastic-beanstalk"
} satisfies RuntimeTest;
