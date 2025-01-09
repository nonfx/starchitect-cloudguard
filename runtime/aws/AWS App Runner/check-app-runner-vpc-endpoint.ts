import {
	AppRunnerClient,
	ListServicesCommand,
	DescribeServiceCommand
} from "@aws-sdk/client-apprunner";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAppRunnerVpcEndpoint(region: string = "us-east-1"): Promise<ComplianceReport> {
	const apprunnerClient = new AppRunnerClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all App Runner services
		let nextToken: string | undefined;
		const servicesList = [];
		do {
			const services = await apprunnerClient.send(
				new ListServicesCommand({ NextToken: nextToken })
			);
			if (services.ServiceSummaryList) {
				servicesList.push(...services.ServiceSummaryList);
			}
			nextToken = services.NextToken;
		} while (nextToken);

		if (!servicesList.length) {
			results.checks.push({
				resourceName: "App Runner Services",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No App Runner services found"
			});
			return results;
		}

		// Check each App Runner service
		for (const serviceSummary of servicesList) {
			if (!serviceSummary.ServiceArn || !serviceSummary.ServiceId) continue;

			const serviceDetails = await apprunnerClient.send(
				new DescribeServiceCommand({
					ServiceArn: serviceSummary.ServiceArn
				})
			);

			const usesVpcConnector =
				serviceDetails.Service?.NetworkConfiguration?.EgressConfiguration?.EgressType === "VPC";

			if (usesVpcConnector) {
				results.checks.push({
					resourceName: serviceSummary.ServiceName || serviceSummary.ServiceId,
					resourceArn: serviceSummary.ServiceArn,
					status: ComplianceStatus.PASS,
					message: undefined
				});
			} else {
				results.checks.push({
					resourceName: serviceSummary.ServiceName || serviceSummary.ServiceId,
					resourceArn: serviceSummary.ServiceArn,
					status: ComplianceStatus.FAIL,
					message: "Service is not using a VPC connector"
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "App Runner Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking App Runner services: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAppRunnerVpcEndpoint(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"App Runner needs access to your application source, so it can't be encrypted. Therefore, be sure to secure the connection between your development or deployment environment and App Runner",
	description:
		"App Runner needs access to your application source, so it can't be encrypted. Therefore, be sure to secure the connection between your development or deployment environment and App Runner",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_10.1",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAppRunnerVpcEndpoint,
	serviceName: "Amazon App Runner",
	shortServiceName: "apprunner"
} satisfies RuntimeTest;
