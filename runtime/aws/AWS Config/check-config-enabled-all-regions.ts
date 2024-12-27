import {
	ConfigServiceClient,
	DescribeConfigurationAggregatorsCommand
} from "@aws-sdk/client-config-service";
import { generateSummary, printSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkConfigEnabledAllRegions(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ConfigServiceClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get configuration aggregators
		const command = new DescribeConfigurationAggregatorsCommand({});
		const response = await client.send(command);

		if (!response.ConfigurationAggregators || response.ConfigurationAggregators.length === 0) {
			results.checks.push({
				resourceName: "AWS Config",
				status: ComplianceStatus.FAIL,
				message: "No configuration aggregators found. AWS Config might not be enabled."
			});
			return results;
		}

		// Check each aggregator
		for (const aggregator of response.ConfigurationAggregators) {
			const aggregatorName = aggregator.ConfigurationAggregatorName || "Unknown Aggregator";

			// Check account aggregation source
			const accountAggregationEnabled = aggregator.AccountAggregationSources?.some(
				source => source.AllAwsRegions === true
			);

			// Check organization aggregation source
			const orgAggregationEnabled =
				aggregator.OrganizationAggregationSource?.AllAwsRegions === true;

			if (accountAggregationEnabled || orgAggregationEnabled) {
				results.checks.push({
					resourceName: aggregatorName,
					status: ComplianceStatus.PASS,
					message: "Config aggregator is properly configured for all regions"
				});
			} else {
				results.checks.push({
					resourceName: aggregatorName,
					status: ComplianceStatus.FAIL,
					message: "Config aggregator is not configured to collect data from all regions"
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "AWS Config",
			status: ComplianceStatus.ERROR,
			message: `Error checking AWS Config: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkConfigEnabledAllRegions(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure AWS Config is enabled in all regions",
	description:
		"AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. The recorded information includes the configuration item (AWS resource), relationships between configuration items (AWS resources), any configuration changes between resources. It is recommended AWS Config be enabled in all regions.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_3.3",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkConfigEnabledAllRegions
} satisfies RuntimeTest;
