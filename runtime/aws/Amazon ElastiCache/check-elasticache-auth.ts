import { ElastiCacheClient, type CacheCluster } from "@aws-sdk/client-elasticache";
import { getCacheClusters } from "./elasticache-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheAuthAndAccess(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ElastiCacheClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all ElastiCache clusters using utility function
		const cacheClusters = await getCacheClusters(client);

		if (cacheClusters.length === 0) {
			results.checks.push({
				resourceName: "No ElastiCache Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ElastiCache clusters found in the region"
			});
			return results;
		}

		// Fetch users and user groups related to the ElastiCache clusters
		for (const cluster of cacheClusters) {
			if (!cluster.CacheClusterId) continue;

			// Check compliance
			const isCompliant = cluster.AuthTokenEnabled === true;

			results.checks.push({
				resourceName: cluster.CacheClusterId,
				resourceArn: cluster.ARN,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant
					? undefined
					: "Authentication and access control is not properly configured for the cluster"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "ElastiCache Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking ElastiCache authentication: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElastiCacheAuthAndAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Authentication and Access Control is Enabled",
	description:
		"Individual creates IAM roles that would give specific permission to what the user can and cannot do within that database. The Access Control List (ACLs) allows only specific individuals to access the resources",
	controls: [
		{
			id: "CIS-AWS-ElastiCache-Benchmark_v1.0.0_5.8",
			document: "CIS-AWS-ElastiCache-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkElastiCacheAuthAndAccess,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elastiCache"
} satisfies RuntimeTest;
