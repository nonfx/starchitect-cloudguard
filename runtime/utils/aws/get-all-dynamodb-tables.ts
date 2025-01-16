import { DynamoDBClient, ListTablesCommand } from "@aws-sdk/client-dynamodb";

export async function getAllDynamoDBTables(client: DynamoDBClient) {
	const tables: string[] = [];
	let lastEvaluatedTableName: string | undefined;

	do {
		const command = new ListTablesCommand({
			Limit: 100, // Maximum allowed value
			ExclusiveStartTableName: lastEvaluatedTableName
		});
		const response = await client.send(command);

		if (response.TableNames) {
			tables.push(...response.TableNames);
		}

		lastEvaluatedTableName = response.LastEvaluatedTableName;
	} while (lastEvaluatedTableName);

	return tables;
}
