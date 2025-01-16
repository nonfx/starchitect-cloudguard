import { DocDBClient, DescribeDBClustersCommand, type DBCluster } from "@aws-sdk/client-docdb";

/**
 * Retrieves all DocumentDB clusters using pagination
 * @param client DocDBClient instance
 * @returns Promise resolving to array of all DB clusters
 */
export const getAllDocDBClusters = async (
	client: DocDBClient,
	filters?: { Name: string; Values: string[] }[]
): Promise<DBCluster[]> => {
	let clusters: DBCluster[] = [];
	let marker: string | undefined;

	do {
		const command = new DescribeDBClustersCommand({
			Marker: marker,
			Filters: filters
		});
		const response = await client.send(command);

		if (response.DBClusters) {
			clusters = clusters.concat(response.DBClusters);
		}

		marker = response.Marker;
	} while (marker);

	return clusters;
};
