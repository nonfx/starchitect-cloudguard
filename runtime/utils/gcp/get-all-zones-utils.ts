import { DNS } from "@google-cloud/dns";

export async function listAllZones(projectId: string): Promise<any[]> {
	const client = new DNS({
		projectId: projectId
	});
	const allZones: any[] = [];
	let nextPageToken: string | undefined;

	do {
		const [zones, , response] = await client.getZones({
			pageToken: nextPageToken,
			maxResults: 100 // Default page size
		});

		if (zones) {
			allZones.push(...zones);
		}

		nextPageToken = response?.nextPageToken || undefined;
	} while (nextPageToken);

	return allZones;
}
