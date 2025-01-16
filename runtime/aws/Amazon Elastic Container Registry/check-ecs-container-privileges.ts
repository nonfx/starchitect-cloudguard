import { ECSClient, DescribeTaskDefinitionCommand } from "@aws-sdk/client-ecs";
import { listAllTaskDefinitions } from "../../utils/aws/ecr-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface ContainerDefinition {
	name?: string | undefined;
	privileged?: boolean;
}

async function checkEcsContainerPrivileges(
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
				const describeCommand = new DescribeTaskDefinitionCommand({
					taskDefinition: taskDefArn
				});
				const taskDef = await client.send(describeCommand);

				if (!taskDef.taskDefinition?.containerDefinitions) {
					results.checks.push({
						resourceName: taskDefArn,
						status: ComplianceStatus.ERROR,
						message: "Task definition has no container definitions"
					});
					continue;
				}

				const privilegedContainers = taskDef.taskDefinition.containerDefinitions
					.filter((container: ContainerDefinition) => container.privileged === true)
					.map((container: ContainerDefinition) => container.name!);

				results.checks.push({
					resourceName: taskDefArn,
					status: privilegedContainers.length === 0 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message:
						privilegedContainers.length > 0
							? `Containers running in privileged mode: ${privilegedContainers.join(", ")}`
							: undefined
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
				resourceName: "ECS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking ECS task definitions: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkEcsContainerPrivileges(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECS containers should run as non-privileged",
	description:
		"This control checks if ECS containers are running with privileged access. Containers should not have privileged access to ensure proper security isolation.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.4",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkEcsContainerPrivileges,
	serviceName: "Amazon Elastic Container Registry",
	shortServiceName: "ecr"
} satisfies RuntimeTest;
