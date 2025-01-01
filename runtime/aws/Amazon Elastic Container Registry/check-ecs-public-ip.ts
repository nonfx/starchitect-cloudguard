import { ECSClient, ListServicesCommand, DescribeServicesCommand } from "@aws-sdk/client-ecs";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEcsPublicIpCompliance(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new ECSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let allServiceArns: string[] = [];

		// Paginate through all ECS services
		do {
			const listServicesResponse = await client.send(
				new ListServicesCommand({
					nextToken
				})
			);

			if (listServicesResponse.serviceArns) {
				allServiceArns = allServiceArns.concat(listServicesResponse.serviceArns);
			}

			nextToken = listServicesResponse.nextToken;
		} while (nextToken);

		if (allServiceArns.length === 0) {
			results.checks.push({
				resourceName: "No ECS Services",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ECS services found in the region"
			});
			return results;
		}

		// Check services in batches of 10 (AWS API limit for DescribeServicesCommand)
		for (let i = 0; i < allServiceArns.length; i += 10) {
			const batch = allServiceArns.slice(i, i + 10);

			const describeServicesResponse = await client.send(
				new DescribeServicesCommand({
					services: batch
				})
			);

			if (!describeServicesResponse.services) continue;

			for (const service of describeServicesResponse.services) {
				if (!service.serviceName || !service.serviceArn) {
					results.checks.push({
						resourceName: "Unknown Service",
						status: ComplianceStatus.ERROR,
						message: "Service found without name or ARN"
					});
					continue;
				}

				const hasPublicIp =
					service.networkConfiguration?.awsvpcConfiguration?.assignPublicIp === "ENABLED";

				results.checks.push({
					resourceName: service.serviceName,
					resourceArn: service.serviceArn,
					status: !hasPublicIp ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasPublicIp
						? "ECS service has automatic public IP assignment enabled"
						: undefined
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "ECS Services Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking ECS services: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkEcsPublicIpCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECS services should not have public IP addresses assigned to them automatically",
	description:
		"This control checks if ECS services are configured to automatically assign public IP addresses. Services with automatic public IP assignment are accessible from the internet, which may pose security risks.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkEcsPublicIpCompliance,
	serviceName: "Amazon Elastic Container Registry",
	shortServiceName: "ecr"
} satisfies RuntimeTest;
