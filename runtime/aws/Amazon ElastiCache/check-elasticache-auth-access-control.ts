import { ElastiCacheClient } from "@aws-sdk/client-elasticache";
import { getCacheClusters } from "./elasticache-utils.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkElastiCacheAuthAccessControl(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const elasticacheClient = new ElastiCacheClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all ElastiCache clusters using utility function
		const cacheClusters = await getCacheClusters(elasticacheClient);

		if (cacheClusters.length === 0) {
			results.checks.push({
				resourceName: "No ElastiCache Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ElastiCache clusters found in the region"
			});
			return results;
		}

		// Process each cluster
		for (const cluster of cacheClusters) {
			if (!cluster.CacheClusterId) continue;

			try {
				// Check if IAM authentication is enabled using AuthTokenEnabled property
				const isIAMAuthEnabled = cluster.AuthTokenEnabled === true;
				const transitEncryptionEnabled = cluster.TransitEncryptionEnabled === true;
				const atRestEncryptionEnabled = cluster.AtRestEncryptionEnabled === true;
				const securityGroups = cluster.SecurityGroups?.map(sg => sg.SecurityGroupId) || [];

				if (
					!isIAMAuthEnabled ||
					!transitEncryptionEnabled ||
					!atRestEncryptionEnabled ||
					securityGroups.length === 0
				) {
					results.checks.push({
						resourceName: cluster.CacheClusterId,
						status: ComplianceStatus.FAIL,
						message: `Authentication or encryption settings are not properly configured, or security groups are missing. AUTH Enabled: ${isIAMAuthEnabled}, Transit Encryption: ${transitEncryptionEnabled}, At Rest Encryption: ${atRestEncryptionEnabled}, Security Groups: ${securityGroups.join(", ")}`
					});
					continue;
				}

				// For ElastiCache with proper configurations, consider it compliant
				results.checks.push({
					resourceName: cluster.CacheClusterId,
					status: ComplianceStatus.PASS,
					message: `Authentication, encryption, and security group settings are properly configured for this cluster. Security Groups: ${securityGroups.join(", ")}`
				});
			} catch (error) {
				results.checks.push({
					resourceName: cluster.CacheClusterId,
					status: ComplianceStatus.ERROR,
					message: `Error checking cluster: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "ElastiCache Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking ElastiCache clusters: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkElastiCacheAuthAccessControl(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Authentication and Access Control is Enabled",
	description:
		"Individual creates IAM roles that would give specific permission to what the user can and cannot do within that database. The Access Control List (ACLs) allows only specific individuals to access the resources",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_5.8",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkElastiCacheAuthAccessControl,
	serviceName: "Amazon ElastiCache",
	shortServiceName: "elastiCache"
} satisfies RuntimeTest;
