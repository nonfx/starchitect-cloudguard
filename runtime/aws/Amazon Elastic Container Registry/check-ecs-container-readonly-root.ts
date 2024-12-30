import {
	DescribeTaskDefinitionCommand,
	ECSClient,
	ListTaskDefinitionsCommand
} from "@aws-sdk/client-ecs";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface ContainerDefinition {
	name: string;
	readonlyRootFilesystem?: boolean;
}

async function checkEcsContainerReadonlyRoot(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ECSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all task definitions
		const listCommand = new ListTaskDefinitionsCommand({});
		const taskDefinitions = await client.send(listCommand);

		if (!taskDefinitions.taskDefinitionArns || taskDefinitions.taskDefinitionArns.length === 0) {
			results.checks = [
				{
					resourceName: "No Task Definitions",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No ECS task definitions found in the region"
				}
			];
			return results;
		}

		// Check each task definition
		for (const taskDefArn of taskDefinitions.taskDefinitionArns) {
			try {
				const describeCommand = new DescribeTaskDefinitionCommand({
					taskDefinition: taskDefArn
				});
				const taskDef = await client.send(describeCommand);

				if (!taskDef.taskDefinition?.containerDefinitions) {
					results.checks.push({
						resourceName: taskDefArn,
						resourceArn: taskDefArn,
						status: ComplianceStatus.ERROR,
						message: "Task definition missing container definitions"
					});
					continue;
				}

				const containers = taskDef.taskDefinition.containerDefinitions as ContainerDefinition[];
				const nonCompliantContainers = containers.filter(
					container => !container.readonlyRootFilesystem
				);

				if (nonCompliantContainers.length > 0) {
					results.checks.push({
						resourceName: taskDefArn,
						resourceArn: taskDefArn,
						status: ComplianceStatus.FAIL,
						message: `Containers without read-only root filesystem: ${nonCompliantContainers
							.map(c => c.name)
							.join(", ")}`
					});
				} else {
					results.checks.push({
						resourceName: taskDefArn,
						resourceArn: taskDefArn,
						status: ComplianceStatus.PASS
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: taskDefArn,
					resourceArn: taskDefArn,
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
				message: `Error checking ECS task definitions: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEcsContainerReadonlyRoot(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECS containers should be limited to read-only access to root filesystems",
	description:
		"This control checks if ECS containers are configured with read-only root filesystem access to prevent unauthorized modifications and enhance security.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEcsContainerReadonlyRoot,
	serviceName: "Amazon Elastic Container Registry",
	shortServiceName: "ecs"
} satisfies RuntimeTest;
