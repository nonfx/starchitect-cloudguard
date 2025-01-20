import logging from "@google-cloud/logging";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface Sink {
	name?: string;
	filter?: string;
	destination?: string;
}

/**
 * Checks if logging sinks are properly configured to export all log entries.
 * This check ensures compliance with CIS Google Cloud Platform Foundation Benchmark v3.0.0 Section 2.2.
 *
 * @returns A compliance report detailing the status of logging sinks configuration
 */
async function checkLoggingSinkCompliance(
	projectId: string = process.env.GCP_PROJECT_ID || ""
): Promise<ComplianceReport> {
	const client = new logging.v2.ConfigServiceV2Client();
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all sinks in the project
		const [sinks] = await client.listSinks({
			parent: `projects/${projectId}`
		});

		if (!sinks || sinks.length === 0) {
			results.checks.push({
				resourceName: "Project Logging Sinks",
				status: ComplianceStatus.FAIL,
				message:
					"No logging sinks found - at least one sink must be configured to export all log entries"
			});
			return results;
		}

		// Find a sink that exports all logs (no filter) to a valid destination
		const validSink = sinks.find((sink: Sink) => {
			if (sink.filter) return false; // Skip sinks with filters
			if (!sink.destination) return false; // Skip sinks without destinations

			// Check if destination is valid (storage bucket, bigquery dataset, or pub/sub topic)
			const dest = sink.destination.toLowerCase();
			return (
				dest.startsWith("storage.googleapis.com/") ||
				dest.startsWith("bigquery.googleapis.com/") ||
				dest.startsWith("pubsub.googleapis.com/")
			);
		});

		if (!validSink) {
			results.checks.push({
				resourceName: "Project Logging Sinks",
				status: ComplianceStatus.FAIL,
				message: "No logging sink found that exports all log entries to a valid destination"
			});
			return results;
		}

		results.checks.push({
			resourceName: validSink.name || "Project Logging Sink",
			status: ComplianceStatus.PASS,
			message: `Valid logging sink configured with destination: ${validSink.destination}`
		});
	} catch (error) {
		results.checks.push({
			resourceName: "Project Logging",
			status: ComplianceStatus.ERROR,
			message: `Error checking logging sinks: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main === true) {
	const projectId = process.env.GCP_PROJECT_ID;
	if (!projectId) {
		throw new Error("GOOGLE_CLOUD_PROJECT environment variable must be set");
	}
	const results = await checkLoggingSinkCompliance(projectId);
	printSummary(generateSummary(results));
}

export default (<RuntimeTest>{
	title: "Ensure That Sinks Are Configured for All Log Entries",
	description:
		"It is recommended to create a sink that will export copies of all the log entries. This can help aggregate logs from multiple projects and export them to a Security Information and Event Management (SIEM).",
	controls: [
		{
			id: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.2",
			document: "CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkLoggingSinkCompliance,
	serviceName: "Cloud Logging",
	shortServiceName: "cloudlogging"
}) satisfies RuntimeTest;
