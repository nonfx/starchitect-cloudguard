import { APIGatewayClient, GetRestApisCommand } from "@aws-sdk/client-api-gateway";
import type { RestApi } from "@aws-sdk/client-api-gateway";

/**
 * Retrieves all REST APIs from API Gateway using pagination
 * @param client The API Gateway client instance
 * @returns Array of all REST APIs
 */
export const getAllRestApis = async (client: APIGatewayClient): Promise<RestApi[]> => {
	const apis: RestApi[] = [];
	let position: string | undefined;

	do {
		const command = new GetRestApisCommand({
			position,
			limit: 500 // Maximum allowed limit per request
		});

		const response = await client.send(command);

		if (response.items) {
			apis.push(...response.items);
		}

		position = response.position;
	} while (position);

	return apis;
};
