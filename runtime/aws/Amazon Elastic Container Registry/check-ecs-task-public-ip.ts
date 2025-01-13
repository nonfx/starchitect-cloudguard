import {
	ECSClient,
	DescribeServicesCommand,
	ListServicesCommand,
	ListClustersCommand
} from "@aws-sdk/client-ecs";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEcsTaskPublicIpCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ECSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// First, list all clusters
		const clusters = await client.send(new ListClustersCommand({}));
		if (!clusters.clusterArns || clusters.clusterArns.length === 0) {
			results.checks.push({
				resourceName: "No ECS Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ECS clusters found in the region"
			});
			return results;
		}

		// For each cluster, list and check its services
		for (const clusterArn of clusters.clusterArns) {
			let nextToken: string | undefined;
			let clusterServices: string[] = [];

			// List all services for this cluster
			do {
				const listServicesResponse = await client.send(
					new ListServicesCommand({
						cluster: clusterArn,
						nextToken
					})
				);

				if (listServicesResponse.serviceArns) {
					clusterServices = clusterServices.concat(listServicesResponse.serviceArns);
				}

				nextToken = listServicesResponse.nextToken;
			} while (nextToken);

			if (clusterServices.length === 0) {
				continue; // Skip clusters with no services
			}

			// Get service details in batches of 10 (AWS API limit)
			for (let i = 0; i < clusterServices.length; i += 10) {
				const batch = clusterServices.slice(i, i + 10);
				const servicesDetails = await client.send(
					new DescribeServicesCommand({
						cluster: clusterArn,
						services: batch
					})
				);

				for (const service of servicesDetails.services || []) {
					if (!service.serviceName || !service.serviceArn) {
						results.checks.push({
							resourceName: "Unknown Service",
							status: ComplianceStatus.ERROR,
							message: "Service found without name or ARN"
						});
						continue;
					}

					// Check network configuration
					const networkConfig = service.networkConfiguration?.awsvpcConfiguration;
					if (!networkConfig) {
						results.checks.push({
							resourceName: service.serviceName,
							resourceArn: service.serviceArn,
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "Service does not use awsvpc network mode"
						});
						continue;
					}

					const assignsPublicIp = networkConfig.assignPublicIp === "ENABLED";

					results.checks.push({
						resourceName: service.serviceName,
						resourceArn: service.serviceArn,
						status: assignsPublicIp ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
						message: assignsPublicIp
							? "Service automatically assigns public IP addresses"
							: undefined
					});
				}
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "ECS Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking ECS services: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkEcsTaskPublicIpCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECS task sets should not automatically assign public IP addresses",
	description:
		"ECS task sets should disable automatic public IP address assignment to prevent unauthorized internet access to container applications.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.16",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkEcsTaskPublicIpCompliance,
	serviceName: "Amazon Elastic Container Registry",
	shortServiceName: "ecr"
} satisfies RuntimeTest;
