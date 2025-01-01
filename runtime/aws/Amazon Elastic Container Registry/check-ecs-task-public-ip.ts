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
		// Get all ECS clusters
		const clusterResponse = await client.send(new ListClustersCommand({}));
		const clusterArns = clusterResponse.clusterArns || [];

		if (clusterArns.length === 0) {
			results.checks.push({
				resourceName: "No ECS Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No ECS clusters found in the region"
			});
			return results;
		}

		// Check each cluster
		for (const clusterArn of clusterArns) {
			// Get services in the cluster
			const servicesResponse = await client.send(
				new ListServicesCommand({
					cluster: clusterArn
				})
			);

			const serviceArns = servicesResponse.serviceArns || [];

			if (serviceArns.length === 0) {
				results.checks.push({
					resourceName: clusterArn,
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No ECS services found in the cluster"
				});
				continue;
			}

			// Get service details in batches of 10 (AWS API limit)
			for (let i = 0; i < serviceArns.length; i += 10) {
				const batch = serviceArns.slice(i, i + 10);
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
