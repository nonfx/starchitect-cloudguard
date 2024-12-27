import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkRdsPostgresCloudWatchLogs(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let marker: string | undefined;
		let instanceFound = false;

		do {
			const command = new DescribeDBInstancesCommand({
				Marker: marker
			});

			const response = await client.send(command);

			if (!response.DBInstances || response.DBInstances.length === 0) {
				if (!instanceFound) {
					results.checks = [
						{
							resourceName: "No RDS Instances",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No RDS instances found in the region"
						}
					];
					return results;
				}
				break;
			}

			for (const instance of response.DBInstances) {
				instanceFound = true;
				const instanceId = instance.DBInstanceIdentifier || "Unknown Instance";

				// Skip non-PostgreSQL instances
				if (!instance.Engine?.toLowerCase().includes("postgres")) {
					continue;
				}

				const enabledLogs = instance.EnabledCloudwatchLogsExports || [];
				const hasPostgresLogs = enabledLogs.includes("postgresql");

				results.checks.push({
					resourceName: instanceId,
					resourceArn: instance.DBInstanceArn,
					status: hasPostgresLogs ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasPostgresLogs
						? undefined
						: `PostgreSQL logs are not fully enabled. Required logs: postgresql, upgrade. Enabled logs: ${enabledLogs.join(", ")}`
				});
			}

			marker = response.Marker;
		} while (marker);

		// If no PostgreSQL instances were found
		if (!results.checks.length) {
			results.checks.push({
				resourceName: "No PostgreSQL Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No PostgreSQL instances found in the region"
			});
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
	const results = await checkRdsPostgresCloudWatchLogs(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS PostgreSQL instances should publish logs to CloudWatch Logs",
	description:
		"This control checks if RDS PostgreSQL instances are configured to publish logs to CloudWatch Logs for monitoring and auditing purposes.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.9",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsPostgresCloudWatchLogs
} satisfies RuntimeTest;
