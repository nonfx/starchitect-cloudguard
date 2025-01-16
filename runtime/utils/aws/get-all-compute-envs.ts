import {
	BatchClient,
	DescribeComputeEnvironmentsCommand,
	type ComputeEnvironmentDetail
} from "@aws-sdk/client-batch";

export async function getAllComputeEnvironments(
	client: BatchClient
): Promise<ComputeEnvironmentDetail[]> {
	const computeEnvironments: ComputeEnvironmentDetail[] = [];
	let nextToken: string | undefined;

	do {
		const command = new DescribeComputeEnvironmentsCommand({
			nextToken
		});
		const response = await client.send(command);

		if (response.computeEnvironments) {
			computeEnvironments.push(...response.computeEnvironments);
		}

		nextToken = response.nextToken;
	} while (nextToken);

	return computeEnvironments;
}
