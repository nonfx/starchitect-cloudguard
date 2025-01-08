import { BatchClient } from "@aws-sdk/client-batch";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllJobDefinitions } from "./get-all-job-definations.js";

interface ContainerProperties {
	logConfiguration?: {
		logDriver?: string;
	};
}

async function checkBatchCloudWatchLogsCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new BatchClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const jobDefinitions = await getAllJobDefinitions(client);

		if (jobDefinitions.length === 0) {
			results.checks = [
				{
					resourceName: "No Batch Job Definitions",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No AWS Batch job definitions found in the region"
				}
			];
			return results;
		}

		for (const jobDef of jobDefinitions) {
			try {
				if (!jobDef.jobDefinitionArn) {
					results.checks.push({
						resourceName: jobDef.jobDefinitionName || "Unknown Job Definition",
						status: ComplianceStatus.ERROR,
						message: "Job definition missing ARN"
					});
					continue;
				}

				if (!jobDef.containerProperties) {
					results.checks.push({
						resourceName: jobDef.jobDefinitionName || "Unknown Job Definition",
						resourceArn: jobDef.jobDefinitionArn,
						status: ComplianceStatus.ERROR,
						message: "Job definition missing container properties"
					});
					continue;
				}

				let containerProps: ContainerProperties;
				try {
					containerProps =
						typeof jobDef.containerProperties === "string"
							? JSON.parse(jobDef.containerProperties)
							: jobDef.containerProperties;
				} catch (parseError) {
					results.checks.push({
						resourceName: jobDef.jobDefinitionName || "Unknown Job Definition",
						resourceArn: jobDef.jobDefinitionArn,
						status: ComplianceStatus.ERROR,
						message: `Error parsing container properties: ${parseError instanceof Error ? parseError.message : String(parseError)}`
					});
					continue;
				}

				const hasCloudWatchLogs = containerProps.logConfiguration?.logDriver === "awslogs";

				results.checks.push({
					resourceName: jobDef.jobDefinitionName || "Unknown Job Definition",
					resourceArn: jobDef.jobDefinitionArn,
					status: hasCloudWatchLogs ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasCloudWatchLogs
						? undefined
						: "Batch job definition is not configured to use CloudWatch Logs"
				});
			} catch (error) {
				results.checks.push({
					resourceName: jobDef.jobDefinitionName || "Unknown Job Definition",
					resourceArn: jobDef.jobDefinitionArn,
					status: ComplianceStatus.ERROR,
					message: `Unexpected error checking job definition: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Batch Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Batch job definitions: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkBatchCloudWatchLogsCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Batch",
	shortServiceName: "batch",
	title: "Ensure AWS Batch is configured with AWS CloudWatch Logs",
	description: "You can configure Batch jobs to send log information to CloudWatch Logs.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_5.1",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkBatchCloudWatchLogsCompliance
} satisfies RuntimeTest;
