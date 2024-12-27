import { AccessAnalyzerClient, ListAnalyzersCommand } from "@aws-sdk/client-accessanalyzer";

import { printSummary, generateSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkAccessAnalyzerEnabled(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new AccessAnalyzerClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// List all analyzers in the region
		const command = new ListAnalyzersCommand({});
		const response = await client.send(command);

		// Check if any active analyzers exist
		const activeAnalyzers = response.analyzers?.filter(analyzer => analyzer.status === "ACTIVE");

		if (!activeAnalyzers || activeAnalyzers.length === 0) {
			results.checks.push({
				resourceName: region,
				status: ComplianceStatus.FAIL,
				message: "No active IAM Access Analyzer found in the region"
			});
			return results;
		}

		// Check each analyzer
		for (const analyzer of activeAnalyzers) {
			if (!analyzer.arn) {
				results.checks.push({
					resourceName: analyzer.name || "Unknown Analyzer",
					status: ComplianceStatus.ERROR,
					message: "Analyzer found without ARN"
				});
				continue;
			}

			results.checks.push({
				resourceName: analyzer.name || "Unknown Analyzer",
				resourceArn: analyzer.arn,
				status: ComplianceStatus.PASS,
				message: undefined
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: region,
			status: ComplianceStatus.ERROR,
			message: `Error checking Access Analyzer: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkAccessAnalyzerEnabled(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure IAM Access Analyzer is enabled for all regions",
	description:
		"Enable IAM Access Analyzer for IAM policies about all resources in each region. IAM Access Analyzer scans policies to show the accessible resources and helps in determining unintended user access.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_1.20",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAccessAnalyzerEnabled
} satisfies RuntimeTest;
