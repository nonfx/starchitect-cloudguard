import {
	ElastiCacheClient,
	DescribeCacheClustersCommand,
	DescribeReplicationGroupsCommand,
	type CacheCluster,
	type ReplicationGroup
} from "@aws-sdk/client-elasticache";

/**
 * Fetches all ElastiCache clusters in a given region with pagination support
 * @param client ElastiCacheClient instance
 * @param showNodeInfo Whether to include detailed node information
 * @returns Array of CacheCluster objects
 */
export async function getCacheClusters(
	client: ElastiCacheClient,
	showNodeInfo: boolean = true
): Promise<CacheCluster[]> {
	let cacheClusters: CacheCluster[] = [];
	let marker: string | undefined;

	do {
		const response = await client.send(
			new DescribeCacheClustersCommand({
				Marker: marker,
				ShowCacheNodeInfo: showNodeInfo
			})
		);

		if (response.CacheClusters) {
			cacheClusters = cacheClusters.concat(response.CacheClusters);
		}
		marker = response.Marker;
	} while (marker);

	return cacheClusters;
}

/**
 * Fetches all ElastiCache replication groups in a given region with pagination support
 * @param client ElastiCacheClient instance
 * @returns Array of ReplicationGroup objects
 */
export async function getReplicationGroups(client: ElastiCacheClient): Promise<ReplicationGroup[]> {
	let replicationGroups: ReplicationGroup[] = [];
	let marker: string | undefined;

	do {
		const response = await client.send(
			new DescribeReplicationGroupsCommand({
				Marker: marker
			})
		);

		if (response.ReplicationGroups) {
			replicationGroups = replicationGroups.concat(response.ReplicationGroups);
		}
		marker = response.Marker;
	} while (marker);

	return replicationGroups;
}
