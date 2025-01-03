import { DAXClient, DescribeClustersCommand } from "@aws-sdk/client-dax";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function getAllDaxClusters(client: DAXClient) {
	const clusters = [];
	let nextToken: string | undefined;

	do {
		const command = new DescribeClustersCommand({
			MaxResults: 100, // Maximum allowed value
			NextToken: nextToken
		});
		const response = await client.send(command);

		if (response.Clusters) {
			clusters.push(...response.Clusters);
		}

		nextToken = response.NextToken;
	} while (nextToken);

	return clusters;
}

async function checkDaxClusterEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new DAXClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const clusters = await getAllDaxClusters(client);

		if (clusters.length === 0) {
			results.checks = [
				{
					resourceName: "No DAX Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No DAX clusters found in the region"
				}
			];
			return results;
		}

		for (const cluster of clusters) {
			if (!cluster.ClusterName || !cluster.ClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without name or ARN"
				});
				continue;
			}

			const isEncrypted = cluster.SSEDescription?.Status === "ENABLED";

			results.checks.push({
				resourceName: cluster.ClusterName,
				resourceArn: cluster.ClusterArn,
				status: isEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isEncrypted ? undefined : "DAX cluster is not encrypted at rest"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "DAX Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking DAX clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkDaxClusterEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon DynamoDB",
	shortServiceName: "dynamodb",
	title: "DynamoDB Accelerator (DAX) clusters should be encrypted at rest",
	description:
		"DynamoDB Accelerator (DAX) clusters must implement encryption at rest to protect data through additional access controls and API permissions.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_DynamoDB.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkDaxClusterEncryption
} satisfies RuntimeTest;
