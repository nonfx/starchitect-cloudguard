import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkRdsMonitoringAndLoggingCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const response = await client.send(new DescribeDBInstancesCommand({}));

		if (!response.DBInstances || response.DBInstances.length === 0) {
			results.checks = [
				{
					resourceName: "No RDS Instances",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No RDS instances found in the region"
				}
			];
			return results;
		}

		for (const instance of response.DBInstances) {
			if (!instance.DBInstanceIdentifier) {
				results.checks.push({
					resourceName: "Unknown Instance",
					status: ComplianceStatus.ERROR,
					message: "RDS instance found without identifier"
				});
				continue;
			}

			const isMonitoringEnabled =
				instance.MonitoringInterval &&
				instance.MonitoringInterval > 0 &&
				instance.MonitoringRoleArn;
			const isLoggingEnabled =
				instance.EnabledCloudwatchLogsExports && instance.EnabledCloudwatchLogsExports.length > 0;

			if (isMonitoringEnabled && isLoggingEnabled) {
				results.checks.push({
					resourceName: instance.DBInstanceIdentifier,
					resourceArn: instance.DBInstanceArn,
					status: ComplianceStatus.PASS
				});
			} else {
				const issues = [];
				if (!isMonitoringEnabled) issues.push("monitoring");
				if (!isLoggingEnabled) issues.push("logging");

				results.checks.push({
					resourceName: instance.DBInstanceIdentifier,
					resourceArn: instance.DBInstanceArn,
					status: ComplianceStatus.FAIL,
					message: `RDS instance does not have ${issues.join(" and ")} enabled`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking RDS instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsMonitoringAndLoggingCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Monitoring and Logging is Enabled",
	description:
		"Ensures that monitoring and logging are enabled for RDS instances to track activity and detect potential security issues.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_3.9",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsMonitoringAndLoggingCompliance
} satisfies RuntimeTest;
