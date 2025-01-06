import { EC2Client, DescribeImagesCommand, type Image } from "@aws-sdk/client-ec2";

/**
 * Retrieves all AMIs using pagination
 * @param client EC2Client instance
 * @param filters Optional filters to apply to the AMI search
 * @returns Promise resolving to array of all AMIs
 */
export const getAllAmis = async (
	client: EC2Client,
	filters?: { Name: string; Values: string[] }[]
): Promise<Image[]> => {
	let images: Image[] = [];
	let nextToken: string | undefined;

	do {
		const command = new DescribeImagesCommand({
			Filters: filters,
			NextToken: nextToken
		});
		const response = await client.send(command);

		if (response.Images) {
			images = images.concat(response.Images);
		}

		nextToken = response.NextToken;
	} while (nextToken);

	return images;
};
