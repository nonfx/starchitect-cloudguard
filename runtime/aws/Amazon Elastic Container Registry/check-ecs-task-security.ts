import {
	ECSClient,
	ListTaskDefinitionsCommand,
	DescribeTaskDefinitionCommand
} from "@aws-sdk/client-ecs";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface ContainerDefinition {
	user?: string;
	privileged?: boolean;
}

function isSecureContainer(containerDef: ContainerDefinition): boolean {
	// Check for non-root user
	if (!containerDef.user || containerDef.user === "" || containerDef.user === "root") {
		return false;
	}

	// Check privileged mode is explicitly false
	if (containerDef.privileged !== false) {
		return false;
	}

	return true;
}

async function checkEcsTaskDefinitionSecurity(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ECSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all task definition ARNs
		const listCommand = new ListTaskDefinitionsCommand({});
		const taskDefinitions = await client.send(listCommand);

		if (!taskDefinitions.taskDefinitionArns || taskDefinitions.taskDefinitionArns.length === 0) {
			results.checks.push({
				resourceName: "No Task Definitions",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ECS task definitions found in the region"
			});
			return results;
		}

		// Check each task definition
		for (const taskDefArn of taskDefinitions.taskDefinitionArns) {
			try {
				const describeCommand = new DescribeTaskDefinitionCommand({
					taskDefinition: taskDefArn
				});
				const taskDef = await client.send(describeCommand);

				if (!taskDef.taskDefinition) {
					results.checks.push({
						resourceName: taskDefArn,
						status: ComplianceStatus.ERROR,
						message: "Unable to retrieve task definition details"
					});
					continue;
				}

				const networkMode = taskDef.taskDefinition.networkMode;
				const containerDefs = taskDef.taskDefinition.containerDefinitions || [];

				// Check security requirements only for host network mode
				if (networkMode === "host") {
					const secureContainers = containerDefs.every(container =>
						isSecureContainer(container as ContainerDefinition)
					);

					results.checks.push({
						resourceName: taskDefArn,
						status: secureContainers ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: secureContainers
							? undefined
							: "Task definition using host network mode must use non-root users and explicitly set privileged=false"
					});
				} else {
					// Other network modes are considered secure
					results.checks.push({
						resourceName: taskDefArn,
						status: ComplianceStatus.PASS
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: taskDefArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking task definition: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "ECS Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking ECS task definitions: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkEcsTaskDefinitionSecurity(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Amazon ECS task definitions should have secure networking modes and user definitions",
	description:
		"This control checks if ECS task definitions use secure networking modes and user definitions to prevent privilege escalation and unauthorized access.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkEcsTaskDefinitionSecurity,
	serviceName: "Amazon Elastic Container Registry",
	shortServiceName: "ecr"
} satisfies RuntimeTest;
