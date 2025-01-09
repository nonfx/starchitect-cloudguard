import { NeptuneClient } from "@aws-sdk/client-neptune";
import { getAllNeptuneClusters } from "./get-all-neptune-clusters.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkNeptuneAuditLogging(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new NeptuneClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const clusters = await getAllNeptuneClusters(client);

		if (clusters.length === 0) {
			results.checks = [
				{
					resourceName: "No Neptune Clusters",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Neptune clusters found in the region"
				}
			];
			return results;
		}

		for (const cluster of clusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			const hasAuditLogging = cluster.EnabledCloudwatchLogsExports?.includes("audit");

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: hasAuditLogging ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasAuditLogging
					? undefined
					: "Audit logging is not enabled for this Neptune cluster"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Neptune Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Neptune clusters: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkNeptuneAuditLogging(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon Neptune",
	shortServiceName: "neptune",
	title: "Ensure Audit Logging is Enabled",
	description:
		"This control is important because it helps ensure activity within the cluster and identifies who has last modified the document and who has access to it, in case of breaches. It also ensures compliance with regulation requirements.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_9.5",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkNeptuneAuditLogging
} satisfies RuntimeTest;
