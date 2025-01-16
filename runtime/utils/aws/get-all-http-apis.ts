import { ApiGatewayV2Client, GetApisCommand } from "@aws-sdk/client-apigatewayv2";
import type { Api } from "@aws-sdk/client-apigatewayv2";

/**
 * Retrieves all HTTP/WebSocket APIs from API Gateway V2 using pagination
 * @param client The API Gateway V2 client instance
 * @returns Array of all APIs
 */
export const getAllHttpApis = async (client: ApiGatewayV2Client): Promise<Api[]> => {
	const apis: Api[] = [];
	let nextToken: string | undefined;

	do {
		const command = new GetApisCommand({
			MaxResults: "100", // Maximum allowed per request
			NextToken: nextToken
		});

		const response = await client.send(command);

		if (response.Items) {
			apis.push(...response.Items);
		}

		nextToken = response.NextToken;
	} while (nextToken);

	return apis;
};
