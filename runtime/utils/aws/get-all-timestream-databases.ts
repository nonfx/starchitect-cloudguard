import { ListDatabasesCommand, TimestreamWrite } from "@aws-sdk/client-timestream-write";
import type { Database } from "@aws-sdk/client-timestream-write";

/**
 * Fetches all Timestream databases with pagination support
 * @param region AWS region
 * @returns Promise resolving to array of Database objects
 */
export async function getAllTimestreamDatabases(region: string): Promise<Database[]> {
	const timestreamWrite = new TimestreamWrite({ region });
	const databases: Database[] = [];
	let nextToken: string | undefined;

	try {
		do {
			const command = new ListDatabasesCommand({
				// MaxResults: 50,
				NextToken: nextToken
			});

			const response = await timestreamWrite.send(command);

			if (response.Databases) {
				databases.push(...response.Databases);
			}

			nextToken = response.NextToken;
		} while (nextToken);

		return databases;
	} catch (error) {
		console.error("Error fetching Timestream databases:", error);
		throw error;
	}
}
