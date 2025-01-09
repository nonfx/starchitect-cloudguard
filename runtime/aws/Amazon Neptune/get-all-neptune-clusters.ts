import { NeptuneClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-neptune";

/**
 * Gets all Neptune DB clusters in the specified region
 * @param client The NeptuneClient instance
 * @returns Array of Neptune DB clusters
 */
export async function getAllNeptuneClusters(client: NeptuneClient): Promise<DBCluster[]> {
	const clusters: DBCluster[] = [];
	let marker: string | undefined;

	try {
		do {
			const command = new DescribeDBClustersCommand({
				Marker: marker
			});

			const response = await client.send(command);

			if (response.DBClusters) {
				clusters.push(...response.DBClusters);
			}

			marker = response.Marker;
		} while (marker);

		return clusters;
	} catch (error) {
		throw new Error(
			`Failed to get Neptune clusters: ${error instanceof Error ? error.message : String(error)}`
		);
	}
}
