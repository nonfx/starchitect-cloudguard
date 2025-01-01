import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// Define required log types per engine
const REQUIRED_LOGS = {
	"oracle-ee": ["alert", "audit"],
	"oracle-se2": ["alert", "audit"],
	postgres: ["postgresql"],
	"aurora-postgresql": ["postgresql"],
	mysql: ["audit"],
	"aurora-mysql": ["audit"],
	mariadb: ["audit"],
	"aurora-mariadb": ["audit"],
	"sqlserver-ee": ["error", "agent"],
	"sqlserver-se": ["error", "agent"],
	"sqlserver-ex": ["error", "agent"],
	"sqlserver-web": ["error", "agent"]
} as const;

type SupportedEngine = keyof typeof REQUIRED_LOGS;

function isSupportedEngine(engine: string): engine is SupportedEngine {
	return Object.keys(REQUIRED_LOGS).includes(engine.toLowerCase());
}

function hasRequiredLogs(engine: string, enabledLogs: string[]): boolean {
	const engineKey = engine.toLowerCase();
	if (!isSupportedEngine(engineKey)) {
		return false;
	}
	return REQUIRED_LOGS[engineKey].every(log => enabledLogs.includes(log));
}

async function checkRdsCloudWatchLogsEnabled(
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

				if (!instance.Engine) {
					results.checks.push({
						resourceName: instanceId,
						status: ComplianceStatus.ERROR,
						message: "Instance engine information not available"
					});
					continue;
				}

				const engineKey = instance.Engine.toLowerCase();
				if (!isSupportedEngine(engineKey)) {
					results.checks.push({
						resourceName: instanceId,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: `Engine type ${instance.Engine} does not require CloudWatch logs`
					});
					continue;
				}

				const enabledLogs = instance.EnabledCloudwatchLogsExports || [];
				const isCompliant = hasRequiredLogs(engineKey, enabledLogs);

				results.checks.push({
					resourceName: instanceId,
					resourceArn: instance.DBInstanceArn,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: `Required CloudWatch logs are not enabled. Required logs for ${instance.Engine}: ${REQUIRED_LOGS[engineKey].join(", ")}`
				});
			}

			marker = response.Marker;
		} while (marker);
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

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsCloudWatchLogsEnabled(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS DB instances should publish logs to CloudWatch Logs",
	description:
		"This control checks if RDS DB instances are configured to publish logs to CloudWatch Logs for monitoring and auditing purposes.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.9",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsCloudWatchLogsEnabled,
	serviceName: "Amazon Relational Database Service",
	shortServiceName: "rds"
} satisfies RuntimeTest;
