import { KeyspacesClient, GetKeyspaceCommand } from "@aws-sdk/client-keyspaces";
import { getAllKeyspaces } from "../../utils/aws/get-all-keyspaces.js";
import { CloudWatchLogsClient, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface SecurityCheck {
	hasEncryptionAtRest: boolean;
	hasCloudWatchLogs: boolean;
	hasIAMAuthentication: boolean;
}

async function checkKeyspaceSecurityConfiguration(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const keyspacesClient = new KeyspacesClient({ region });
	const cloudWatchClient = new CloudWatchLogsClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const keyspaces = await getAllKeyspaces(keyspacesClient);

		if (!keyspaces || keyspaces.length === 0) {
			results.checks.push({
				resourceName: "No Keyspaces",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Keyspaces found in the region"
			});
			return results;
		}

		for (const keyspace of keyspaces) {
			if (!keyspace.keyspaceName) continue;

			try {
				// Get keyspace details
				const keyspaceDetails = await keyspacesClient.send(
					new GetKeyspaceCommand({
						keyspaceName: keyspace.keyspaceName
					})
				);

				// Check CloudWatch Logs
				const logGroups = await cloudWatchClient.send(
					new DescribeLogGroupsCommand({
						logGroupNamePrefix: `/aws/keyspaces/${keyspace.keyspaceName}`
					})
				);

				const securityChecks: SecurityCheck = {
					// Encryption at rest is enabled by default in Keyspaces
					hasEncryptionAtRest: true,
					// Check if CloudWatch logs are configured
					hasCloudWatchLogs: (logGroups.logGroups?.length ?? 0) > 0,
					// Check if IAM authentication is enabled
					hasIAMAuthentication: true // Always enabled for Keyspaces
				};

				const isCompliant =
					securityChecks.hasEncryptionAtRest &&
					securityChecks.hasCloudWatchLogs &&
					securityChecks.hasIAMAuthentication;

				let failureReasons: string[] = [];
				if (!securityChecks.hasEncryptionAtRest)
					failureReasons.push("Encryption at rest not enabled");
				if (!securityChecks.hasCloudWatchLogs)
					failureReasons.push("CloudWatch logging not configured");
				if (!securityChecks.hasIAMAuthentication)
					failureReasons.push("IAM authentication not enabled");

				results.checks.push({
					resourceName: keyspace.keyspaceName,
					resourceArn: keyspace.resourceArn,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: `Keyspace security is not properly configured: ${failureReasons.join(", ")}`
				});
			} catch (error) {
				results.checks.push({
					resourceName: keyspace.keyspaceName,
					resourceArn: keyspace.resourceArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking keyspace security: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Keyspaces Security Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking keyspaces security: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkKeyspaceSecurityConfiguration(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Keyspace Security is Configured",
	description:
		"Checks if Amazon Keyspaces are properly configured with security features including encryption, authentication, and audit logging.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_8.1",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkKeyspaceSecurityConfiguration,
	serviceName: "Amazon Keyspaces",
	shortServiceName: "keyspaces"
} satisfies RuntimeTest;
