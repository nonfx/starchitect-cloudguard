import {
	BatchClient,
	DescribeJobDefinitionsCommand,
	type JobDefinition
} from "@aws-sdk/client-batch";

export async function getAllJobDefinitions(client: BatchClient): Promise<JobDefinition[]> {
	const jobDefinitions: JobDefinition[] = [];
	let nextToken: string | undefined;

	do {
		const command = new DescribeJobDefinitionsCommand({
			nextToken
		});
		const response = await client.send(command);

		if (response.jobDefinitions) {
			jobDefinitions.push(...response.jobDefinitions);
		}

		nextToken = response.nextToken;
	} while (nextToken);

	return jobDefinitions;
}
