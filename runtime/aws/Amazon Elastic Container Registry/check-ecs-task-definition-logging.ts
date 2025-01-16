import { ECSClient, DescribeTaskDefinitionCommand } from "@aws-sdk/client-ecs";
import { listAllTaskDefinitions } from "../../utils/aws/ecr-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface ContainerDefinition {
	name: string;
	logConfiguration?: {
		logDriver?: string;
	};
}

async function checkEcsTaskDefinitionLogging(
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

				const containerDefs = taskDef.taskDefinition.containerDefinitions as ContainerDefinition[];
				const allContainersHaveLogging = containerDefs.every(
					container => container.logConfiguration?.logDriver !== undefined
				);

				results.checks.push({
					resourceName: taskDefArn,
					status: allContainersHaveLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: allContainersHaveLogging
						? undefined
						: "One or more containers in the task definition do not have logging configuration"
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
	const results = await checkEcsTaskDefinitionLogging(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECS task definitions should have a logging configuration",
	description:
		"ECS task definitions must include logging configuration to maintain visibility and debugging capabilities for container applications.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.9",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkEcsTaskDefinitionLogging,
	serviceName: "Amazon Elastic Container Registry",
	shortServiceName: "ecr"
} satisfies RuntimeTest;
