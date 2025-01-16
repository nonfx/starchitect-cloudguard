import { Storage } from "@google-cloud/storage";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkStorageBucketRetentionCompliance(): Promise<ComplianceReport> {
	const storage = new Storage();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const [buckets] = await storage.getBuckets({ autoPaginate: true });

		if (!buckets || buckets.length === 0) {
			results.checks = [
				{
					resourceName: "No Storage Buckets",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No storage buckets found in the project"
				}
			];
			return results;
		}

		for (const bucket of buckets) {
			try {
				const [metadata] = await bucket.getMetadata();
				const retentionPolicy = metadata.retentionPolicy;

				const hasValidRetention =
					retentionPolicy &&
					retentionPolicy.isLocked === true &&
					Number(retentionPolicy.retentionPeriod) > 0;

				results.checks.push({
					resourceName: bucket.name,
					status: hasValidRetention ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasValidRetention
						? undefined
						: "Storage bucket must have a retention policy configured with Bucket Lock enabled and a retention period greater than 0"
				});
			} catch (error) {
				results.checks.push({
					resourceName: bucket.name,
					status: ComplianceStatus.ERROR,
					message: `Error checking bucket retention policy: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Project Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking storage buckets: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const results = await checkStorageBucketRetentionCompliance();
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure That Retention Policies on Cloud Storage Buckets Used for Exporting Logs Are Configured Using Bucket Lock",
	description:
		"Storage buckets used for exporting logs must have retention policies configured with Bucket Lock to prevent unauthorized deletion of logs.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.3",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "HIGH",
	execute: checkStorageBucketRetentionCompliance,
	// cloudProvider: 'gcp',
	serviceName: "Cloud Storage",
	shortServiceName: "storage"
} satisfies RuntimeTest;
