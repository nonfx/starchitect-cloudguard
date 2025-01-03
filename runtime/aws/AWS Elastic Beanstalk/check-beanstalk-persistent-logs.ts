import {
	ElasticBeanstalkClient,
	DescribeEnvironmentsCommand,
	DescribeConfigurationSettingsCommand
} from "@aws-sdk/client-elastic-beanstalk";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkBeanstalkPersistentLogs(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ElasticBeanstalkClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all Elastic Beanstalk environments
		const environments = await client.send(new DescribeEnvironmentsCommand({}));

		if (!environments.Environments || environments.Environments.length === 0) {
			results.checks = [
				{
					resourceName: "No Elastic Beanstalk Environments",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Elastic Beanstalk environments found in the region"
				}
			];
			return results;
		}

		for (const env of environments.Environments) {
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

				const settings = configSettings.ConfigurationSettings?.[0]?.OptionSettings || [];

				// Check log streaming configuration
				const streamLogs = settings.find(
					s =>
						s.Namespace === "aws:elasticbeanstalk:cloudwatch:logs" && s.OptionName === "StreamLogs"
				);
				const retentionDays = settings.find(
					s =>
						s.Namespace === "aws:elasticbeanstalk:cloudwatch:logs" &&
						s.OptionName === "RetentionInDays"
				);
				const deleteOnTerminate = settings.find(
					s =>
						s.Namespace === "aws:elasticbeanstalk:cloudwatch:logs" &&
						s.OptionName === "DeleteOnTerminate"
				);

				const isCompliant =
					streamLogs?.Value === "true" &&
					parseInt(retentionDays?.Value || "0") > 0 &&
					deleteOnTerminate?.Value === "false";

				let message;
				if (!isCompliant) {
					const issues = [];
					if (streamLogs?.Value !== "true") issues.push("Log streaming is not enabled");
					if (!retentionDays?.Value || parseInt(retentionDays.Value) <= 0)
						issues.push("Log retention is not configured");
					if (deleteOnTerminate?.Value !== "false")
						issues.push("Logs are not kept after termination");
					message = issues.join(", ");
				}

				results.checks.push({
					resourceName: env.EnvironmentName,
					resourceArn: env.EnvironmentArn,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: message
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
	const results = await checkBeanstalkPersistentLogs(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Persistent logs is setup and configured to S3",
	description:
		"Elastic Beanstalk can be configured to automatically stream logs to the CloudWatch service. With CloudWatch Logs, you can monitor and archive your Elastic Beanstalk application, system, and custom log files from Amazon EC2 instances of your environments.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_6.2",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkBeanstalkPersistentLogs,
	serviceName: "AWS Elastic Beanstalk",
	shortServiceName: "elastic-beanstalk"
} satisfies RuntimeTest;
