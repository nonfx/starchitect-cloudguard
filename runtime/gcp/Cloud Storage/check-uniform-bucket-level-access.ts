import { Storage } from "@google-cloud/storage";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkUniformBucketLevelAccess(): Promise<ComplianceReport> {
	const storage = new Storage();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all buckets
		const [buckets] = await storage.getBuckets({ autoPaginate: true });

		if (!buckets || buckets.length === 0) {
			results.checks = [
				{
					resourceName: "No Storage Buckets",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Cloud Storage buckets found"
				}
			];
			return results;
		}

		// Check each bucket's uniform bucket-level access setting
		for (const bucket of buckets) {
			try {
				const [metadata] = await bucket.getMetadata();
				const isUniformAccessEnabled = metadata.iamConfiguration?.uniformBucketLevelAccess?.enabled;

				results.checks.push({
					resourceName: bucket.name,
					status: isUniformAccessEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: isUniformAccessEnabled
						? undefined
						: "Uniform bucket-level access is not enabled for this bucket"
				});
			} catch (error) {
				results.checks.push({
					resourceName: bucket.name,
					status: ComplianceStatus.ERROR,
					message: `Error checking bucket metadata: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Storage Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Cloud Storage buckets: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const results = await checkUniformBucketLevelAccess();
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure uniform bucket-level access is enabled for Cloud Storage buckets",
	description:
		"Uniform bucket-level access ensures consistent use of IAM permissions and simplifies access management.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_5.2",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkUniformBucketLevelAccess,
	// cloudProvider: 'gcp',
	serviceName: "Cloud Storage",
	shortServiceName: "storage"
} satisfies RuntimeTest;
