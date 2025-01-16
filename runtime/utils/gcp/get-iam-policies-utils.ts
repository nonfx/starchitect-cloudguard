import { ProjectsClient } from "@google-cloud/resource-manager";

export async function getProjectPolicy(projectId: string): Promise<any> {
	const client = new ProjectsClient();

	try {
		const [policy] = await client.getIamPolicy({
			resource: `projects/${projectId}`,
			options: {
				requestedPolicyVersion: 3 // Latest policy version
			}
		});
		return policy;
	} catch (error) {
		console.error("Error getting project policy:", error);
		throw error;
	}
}

// Both checks use Resource Manager API's getIamPolicy
export async function getIAMPolicy(projectId: string): Promise<any> {
	return getProjectPolicy(projectId);
}
