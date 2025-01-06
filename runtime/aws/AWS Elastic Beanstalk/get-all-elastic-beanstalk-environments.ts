import {
	ElasticBeanstalkClient,
	DescribeEnvironmentsCommand,
	type DescribeEnvironmentsCommandOutput
} from "@aws-sdk/client-elastic-beanstalk";

export const getAllBeanstalkEnvironments = async (
	client: ElasticBeanstalkClient
): Promise<DescribeEnvironmentsCommandOutput["Environments"]> => {
	let environments: NonNullable<DescribeEnvironmentsCommandOutput["Environments"]> = [];
	let nextToken: string | undefined;

	do {
		const command = new DescribeEnvironmentsCommand({
			NextToken: nextToken
		});
		const response = await client.send(command);

		if (response.Environments) {
			environments = environments.concat(response.Environments);
		}

		nextToken = response.NextToken;
	} while (nextToken);

	return environments;
};
