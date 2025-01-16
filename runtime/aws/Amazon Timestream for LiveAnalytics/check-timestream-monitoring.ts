import {
	CloudWatchClient,
	DescribeAlarmsCommand,
	type MetricAlarm
} from "@aws-sdk/client-cloudwatch";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllTimestreamDatabases } from "../../utils/aws/get-all-timestream-databases.js";

async function checkTimestreamMonitoringCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const cloudwatchClient = new CloudWatchClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check if Timestream databases exist
		const databases = await getAllTimestreamDatabases(region);

		if (databases.length === 0) {
			results.checks.push({
				resourceName: "Timestream Databases",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Timestream databases found"
			});
			return results;
		}

		// Get all CloudWatch alarms
		let nextToken: string | undefined;
		let allAlarms: MetricAlarm[] = [];

		do {
			const alarmsResponse = await cloudwatchClient.send(
				new DescribeAlarmsCommand({
					NextToken: nextToken
				})
			);

			if (alarmsResponse.MetricAlarms) {
				allAlarms = [...allAlarms, ...alarmsResponse.MetricAlarms];
			}

			nextToken = alarmsResponse.NextToken;
		} while (nextToken);

		// Check alarms for each database
		for (const database of databases) {
			if (!database.DatabaseName) continue;

			const timestreamAlarms = allAlarms.filter(
				alarm =>
					alarm.Namespace === "AWS/Timestream" &&
					alarm.Dimensions?.some(
						d => d.Name === "DatabaseName" && d.Value === database.DatabaseName
					)
			);

			if (timestreamAlarms.length === 0) {
				results.checks.push({
					resourceName: database.DatabaseName,
					resourceArn: database.Arn,
					status: ComplianceStatus.FAIL,
					message: "No CloudWatch alarms configured for this Timestream database"
				});
			} else {
				results.checks.push({
					resourceName: database.DatabaseName,
					resourceArn: database.Arn,
					status: ComplianceStatus.PASS,
					message: `${timestreamAlarms.length} CloudWatch alarm(s) configured`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Monitoring Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Timestream monitoring: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkTimestreamMonitoringCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Monitoring and Alerting is Enabled - alerting",
	description:
		"Utilize Amazon CloudWatch to monitor key metrics, events, and logs related to Amazon Timestream. Set up appropriate alarms and notifications to detect security incidents or abnormal behavior proactively",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_10.8",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkTimestreamMonitoringCompliance,
	serviceName: "Amazon Timestream for LiveAnalytics",
	shortServiceName: "timestream"
} satisfies RuntimeTest;
