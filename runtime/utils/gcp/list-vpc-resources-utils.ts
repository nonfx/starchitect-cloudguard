import { NetworksClient, FirewallsClient, SubnetworksClient } from "@google-cloud/compute";

export async function listAllNetworks(projectId: string): Promise<any[]> {
	const client = new NetworksClient();
	const allNetworks: any[] = [];
	let nextPageToken: string | undefined;

	do {
		const [networks, , response] = await client.list({
			project: projectId,
			pageToken: nextPageToken
		});

		if (networks) {
			allNetworks.push(...networks);
		}

		nextPageToken = response?.nextPageToken || undefined;
	} while (nextPageToken);

	return allNetworks;
}

export async function listAllFirewalls(projectId: string): Promise<any[]> {
	const client = new FirewallsClient();
	const allFirewalls: any[] = [];
	let nextPageToken: string | undefined;

	do {
		const [firewalls, , response] = await client.list({
			project: projectId,
			pageToken: nextPageToken
		});

		if (firewalls) {
			allFirewalls.push(...firewalls);
		}

		nextPageToken = response?.nextPageToken || undefined;
	} while (nextPageToken);

	return allFirewalls;
}

export async function listAllSubnets(projectId: string, region: string): Promise<any[]> {
	const client = new SubnetworksClient();
	const allSubnets: any[] = [];
	let nextPageToken: string | undefined;

	do {
		const [subnets, , response] = await client.list({
			project: projectId,
			region,
			pageToken: nextPageToken
		});

		if (subnets) {
			allSubnets.push(...subnets);
		}

		nextPageToken = response?.nextPageToken || undefined;
	} while (nextPageToken);

	return allSubnets;
}
