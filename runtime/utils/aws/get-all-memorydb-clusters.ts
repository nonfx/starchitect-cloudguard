import { MemoryDBClient, DescribeClustersCommand, type Cluster } from "@aws-sdk/client-memorydb";

export async function getAllMemoryDBClusters(client: MemoryDBClient) {
	const clusters: Cluster[] = [];
	let nextToken: string | undefined;

	do {
		const command = new DescribeClustersCommand({
			MaxResults: 100, // Maximum allowed value
			NextToken: nextToken
		});
		const response = await client.send(command);

		if (response.Clusters) {
			clusters.push(...response.Clusters);
		}

		nextToken = response.NextToken;
	} while (nextToken);

	return clusters;
}
