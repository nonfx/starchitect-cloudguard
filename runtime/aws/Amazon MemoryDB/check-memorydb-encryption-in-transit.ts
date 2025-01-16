import { MemoryDBClient, DescribeClustersCommand } from "@aws-sdk/client-memorydb";
import { getAllMemoryDBClusters } from "../../utils/aws/get-all-memorydb-clusters.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkMemoryDBEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new MemoryDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all MemoryDB clusters
		const clusters = await getAllMemoryDBClusters(client);
		if (clusters.length === 0) {
			results.checks = [
				{
					resourceName: "No MemoryDB Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No MemoryDB clusters found in the region"
				}
			];
			return results;
		}

		for (const cluster of clusters) {
			if (!cluster.Name || !cluster.ARN) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without name or ARN"
				});
				continue;
			}

			const isEncrypted = cluster.TLSEnabled === true;

			results.checks.push({
				resourceName: cluster.Name,
				resourceArn: cluster.ARN,
				status: isEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isEncrypted ? undefined : "MemoryDB cluster is not encrypted in transit"
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
	const results = await checkMemoryDBEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon MemoryDB",
	shortServiceName: "memorydb",
	title: "Ensure Data at Rest and in Transit is Encrypted - in transit",
	description: ".",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_6.2",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkMemoryDBEncryption
} satisfies RuntimeTest;
