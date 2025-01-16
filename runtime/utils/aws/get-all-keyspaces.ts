import {
	KeyspacesClient,
	ListKeyspacesCommand,
	type ListKeyspacesCommandOutput
} from "@aws-sdk/client-keyspaces";

/**
 * Get all keyspaces in a region
 * @param client KeyspacesClient instance
 * @returns Array of keyspaces or undefined if none found
 */
export async function getAllKeyspaces(
	client: KeyspacesClient
): Promise<NonNullable<ListKeyspacesCommandOutput["keyspaces"]> | undefined> {
	try {
		const response = await client.send(new ListKeyspacesCommand({}));
		return response.keyspaces;
	} catch (error) {
		console.error("Error listing keyspaces:", error);
		throw error;
	}
}
