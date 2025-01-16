import { ECSClient, DescribeTaskDefinitionCommand } from "@aws-sdk/client-ecs";
import { listAllTaskDefinitions } from "../../utils/aws/ecr-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// List of sensitive environment variable names to check
const SENSITIVE_ENV_VARS = [
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"ECS_ENGINE_AUTH_DATA",
	"PASSWORD",
	"SECRET",
	"KEY"
];

// Regex pattern for AWS access key format
const AWS_ACCESS_KEY_PATTERN =
	/^(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}$/;

function isSensitiveEnvVar(name: string): boolean {
	return SENSITIVE_ENV_VARS.some(sensitive => name.toLowerCase().includes(sensitive.toLowerCase()));
}

function isSensitiveValue(value: string): boolean {
	return AWS_ACCESS_KEY_PATTERN.test(value);
}

async function checkEcsSecretEnvVars(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new ECSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const { taskDefinitionArns, baseReport } = await listAllTaskDefinitions(client);
		if (baseReport) {
			return baseReport;
		}

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

				let hasSensitiveEnvVars = false;
				for (const container of taskDef.taskDefinition.containerDefinitions) {
					if (container.environment) {
						for (const env of container.environment) {
							if (
								env.name &&
								(isSensitiveEnvVar(env.name) || (env.value && isSensitiveValue(env.value)))
							) {
								hasSensitiveEnvVars = true;
								break;
							}
						}
					}
				}

				results.checks.push({
					resourceName: taskDefArn,
					status: hasSensitiveEnvVars ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasSensitiveEnvVars
						? "Task definition contains sensitive information in environment variables"
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
		results.checks.push({
			resourceName: "Region Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking ECS task definitions: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkEcsSecretEnvVars(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Secrets should not be passed as container environment variables",
	description:
		"ECS task definitions should avoid passing secrets as environment variables and instead use AWS Systems Manager Parameter Store for secure credential management.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.8",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkEcsSecretEnvVars,
	serviceName: "Amazon Elastic Container Registry",
	shortServiceName: "ecr"
} satisfies RuntimeTest;
