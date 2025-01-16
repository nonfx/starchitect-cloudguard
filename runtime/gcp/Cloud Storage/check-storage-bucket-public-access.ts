import { Storage } from "@google-cloud/storage";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkStorageBucketPublicAccess(): Promise<ComplianceReport> {
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
					message: "No storage buckets found in the project"
				}
			];
			return results;
		}

		// Check each bucket's IAM policy
		for (const bucket of buckets) {
			try {
				const [policy] = await bucket.iam.getPolicy();

				let hasPublicAccess = false;

				// Check for public access in bindings
				if (policy.bindings) {
					for (const binding of policy.bindings) {
						if (
							binding.members?.some(
								member => member === "allUsers" || member === "allAuthenticatedUsers"
							)
						) {
							hasPublicAccess = true;
							break;
						}
					}
				}

				results.checks.push({
					resourceName: bucket.name,
					status: hasPublicAccess ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasPublicAccess ? "Bucket has public access through IAM policy" : undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: bucket.name,
					status: ComplianceStatus.ERROR,
					message: `Error checking bucket IAM policy: ${error instanceof Error ? error.message : String(error)}`
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
	}

	return results;
}

if (import.meta.main) {
	const results = await checkStorageBucketPublicAccess();
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure That Cloud Storage Bucket Is Not Anonymously or Publicly Accessible",
	description:
		"Cloud Storage buckets should not allow anonymous or public access to prevent unauthorized data exposure. IAM policies should be properly configured to restrict access.",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_5.1",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "CRITICAL",
	execute: checkStorageBucketPublicAccess,
	// cloudProvider: "gcp",
	serviceName: "Cloud Storage",
	shortServiceName: "storage"
} satisfies RuntimeTest;
