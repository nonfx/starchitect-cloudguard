import { ECSClient, DescribeTaskDefinitionCommand } from "@aws-sdk/client-ecs";
import { listAllTaskDefinitions } from "../../utils/aws/ecr-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEcsTaskDefinitionPidMode(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ECSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const { taskDefinitionArns, baseReport } = await listAllTaskDefinitions(client);
		if (baseReport) {
			return baseReport;
		}

		// Check each task definition
		for (const taskDefArn of taskDefinitionArns) {
			try {
				const taskDef = await client.send(
					new DescribeTaskDefinitionCommand({
						taskDefinition: taskDefArn
					})
				);

				if (!taskDef.taskDefinition) {
					results.checks.push({
						resourceName: taskDefArn,
						status: ComplianceStatus.ERROR,
						message: "Unable to retrieve task definition details"
					});
					continue;
				}

				const pidMode = taskDef.taskDefinition.pidMode;
				const isCompliant = !pidMode || pidMode !== "host";

				results.checks.push({
					resourceName: taskDefArn,
					status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isCompliant
						? undefined
						: "Task definition shares host process namespace (pidMode: host)"
				});
			} catch (error) {
				results.checks.push({
					resourceName: taskDefArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking task definition: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error listing task definitions: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkEcsTaskDefinitionPidMode(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECS task definitions should not share the host's process namespace",
	description:
		"This control checks if ECS task definitions share the host's process namespace with containers. Sharing the host's process namespace reduces process isolation and could allow unauthorized access to host system processes.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkEcsTaskDefinitionPidMode,
	serviceName: "Amazon Elastic Container Registry",
	shortServiceName: "ecr"
} satisfies RuntimeTest;
