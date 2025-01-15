import { InstancesClient, DisksClient, ProjectsClient } from "@google-cloud/compute";

export async function listAllInstances(projectId: string, zone: string): Promise<any[]> {
	const client = new InstancesClient();
	const allInstances: any[] = [];
	let nextPageToken: string | undefined;

	do {
		const [instances, , response] = await client.list({
			project: projectId,
			zone,
			pageToken: nextPageToken
		});

		if (instances) {
			allInstances.push(...instances);
		}

		nextPageToken = response?.nextPageToken || undefined;
	} while (nextPageToken);

	return allInstances;
}

export async function listAllDisks(projectId: string, zone: string): Promise<any[]> {
	const client = new DisksClient();
	const allDisks: any[] = [];
	let nextPageToken: string | undefined;

	do {
		const [disks, , response] = await client.list({
			project: projectId,
			zone,
			pageToken: nextPageToken
		});

		if (disks) {
			allDisks.push(...disks);
		}

		nextPageToken = response?.nextPageToken || undefined;
	} while (nextPageToken);

	return allDisks;
}

export async function getProject(projectId: string): Promise<any> {
	const client = new ProjectsClient();
	const [project] = await client.get({
		project: projectId
	});
	return project || null;
}
