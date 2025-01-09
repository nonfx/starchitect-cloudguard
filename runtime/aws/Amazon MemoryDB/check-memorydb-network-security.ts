import { MemoryDBClient, DescribeClustersCommand } from "@aws-sdk/client-memorydb";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkMemoryDBNetworkSecurity(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new MemoryDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const command = new DescribeClustersCommand({});
		const response = await client.send(command);

		if (!response.Clusters || response.Clusters.length === 0) {
			results.checks = [
				{
					resourceName: "No MemoryDB Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No MemoryDB clusters found in the region"
				}
			];
			return results;
		}

		for (const cluster of response.Clusters) {
			if (!cluster.Name) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without name"
				});
				continue;
			}

			const hasSubnetGroup = cluster.SubnetGroupName ? true : false;
			const hasSecurityGroups = cluster.SecurityGroups && cluster.SecurityGroups.length > 0;
			const isCompliant = hasSubnetGroup && hasSecurityGroups;

			results.checks.push({
				resourceName: cluster.Name,
				resourceArn: cluster.ARN,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant
					? undefined
					: "Network security is not properly enabled for this Amazon MemoryDB cluster"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "MemoryDB Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking MemoryDB clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkMemoryDBNetworkSecurity(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon MemoryDB",
	shortServiceName: "memorydb",
	title: "Ensure Network Security is Enabled",
	description: "",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_6.1",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkMemoryDBNetworkSecurity
} satisfies RuntimeTest;
