import { DescribeRepositoriesCommand, ECRClient } from "@aws-sdk/client-ecr";
import { ECSClient, ListTaskDefinitionsCommand, type TaskDefinition } from "@aws-sdk/client-ecs";
import { ComplianceStatus, type ComplianceReport } from "../../types.js";

export interface ECRRepository {
	repositoryName?: string;
	repositoryArn?: string;
	imageScanningConfiguration?: {
		scanOnPush?: boolean;
	};
	imageTagMutability?: string;
}
export async function fetchECRRepositories(client: ECRClient): Promise<ECRRepository[]> {
	let nextToken: string | undefined;
	let repositories: ECRRepository[] = [];

	try {
		do {
			const response = await client.send(
				new DescribeRepositoriesCommand({
					nextToken
				})
			);

			if (response.repositories) {
				repositories = repositories.concat(response.repositories);
			}

			nextToken = response.nextToken;
		} while (nextToken);

		return repositories;
	} catch (error) {
		throw new Error(
			`Error fetching ECR repositories: ${error instanceof Error ? error.message : String(error)}`
		);
	}
}

/**
 * Lists all ECS task definitions in a given region
 * @param client - The ECS client instance
 * @returns Array of task definition ARNs and a base compliance report if no definitions found
 */
export async function listAllTaskDefinitions(client: ECSClient): Promise<{
	taskDefinitionArns: string[];
	baseReport?: ComplianceReport;
}> {
	let nextToken: string | undefined;
	let taskDefinitionArns: string[] = [];

	try {
		do {
			// List all task definitions
			const listCommand = new ListTaskDefinitionsCommand({
				nextToken
			});
			const response = await client.send(listCommand);

			if (response.taskDefinitionArns) {
				taskDefinitionArns = taskDefinitionArns.concat(response.taskDefinitionArns);
			}
			nextToken = response.nextToken;
		} while (nextToken);

		if (taskDefinitionArns.length === 0) {
			return {
				taskDefinitionArns: [],
				baseReport: {
					checks: [
						{
							resourceName: "No Task Definitions",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No ECS task definitions found in the region"
						}
					]
				}
			};
		}

		return { taskDefinitionArns };
	} catch (error) {
		return {
			taskDefinitionArns: [],
			baseReport: {
				checks: [
					{
						resourceName: "Region Check",
						status: ComplianceStatus.ERROR,
						message: `Error listing task definitions: ${error instanceof Error ? error.message : String(error)}`
					}
				]
			}
		};
	}
}
