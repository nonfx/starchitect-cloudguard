import { ApiKeysClient } from "@google-cloud/apikeys";

export async function listAllKeys(projectId: string): Promise<any[]> {
	const client = new ApiKeysClient();
	const allKeys: any[] = [];
	let nextPageToken: string | undefined;

	do {
		const [keys, , response] = await client.listKeys({
			parent: `projects/${projectId}/locations/global`,
			pageToken: nextPageToken
		});

		if (keys) {
			allKeys.push(...keys);
		}

		nextPageToken = response?.nextPageToken || undefined;
	} while (nextPageToken);

	return allKeys;
}
