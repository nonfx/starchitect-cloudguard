import {
	CloudFrontClient,
	ListDistributionsCommand,
	type DistributionSummary
} from "@aws-sdk/client-cloudfront";

/**
 * Retrieves all CloudFront distributions using pagination
 * @param client CloudFrontClient instance
 * @returns Promise resolving to array of all distributions
 */
export const getAllCloudFrontDistributions = async (
	client: CloudFrontClient
): Promise<DistributionSummary[]> => {
	let distributions: DistributionSummary[] = [];
	let nextMarker: string | undefined;

	do {
		const command = new ListDistributionsCommand({
			Marker: nextMarker
		});
		const response = await client.send(command);

		if (response.DistributionList?.Items) {
			distributions = distributions.concat(response.DistributionList.Items);
		}

		nextMarker = response.DistributionList?.NextMarker;
	} while (nextMarker);

	return distributions;
};
