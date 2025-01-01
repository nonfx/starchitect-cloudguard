import { ECSClient, ListServicesCommand, DescribeServicesCommand } from "@aws-sdk/client-ecs";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const LATEST_VERSIONS = {
	LINUX: ["1.4.0", "LATEST"],
	WINDOWS: ["1.0.0"]
};

function isLatestVersion(platformVersion: string): boolean {
	return (
		LATEST_VERSIONS.LINUX.includes(platformVersion) ||
		LATEST_VERSIONS.WINDOWS.includes(platformVersion)
	);
}

async function checkEcsFargatePlatformVersion(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ECSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// List all clusters first (empty array means default cluster)
		const clusters = ["default"];

		for (const cluster of clusters) {
			// List services in the cluster
			const listServicesCommand = new ListServicesCommand({
				cluster: cluster
			});

			try {
				const servicesResponse = await client.send(listServicesCommand);
				const serviceArns = servicesResponse.serviceArns || [];

				if (serviceArns.length === 0) {
					results.checks.push({
						resourceName: `Cluster: ${cluster}`,
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No ECS services found in the cluster"
					});
					continue;
				}

				// Get service details
				const describeServicesCommand = new DescribeServicesCommand({
					cluster: cluster,
					services: serviceArns
				});

				const servicesDetails = await client.send(describeServicesCommand);

				if (!servicesDetails.services) {
					continue;
				}

				for (const service of servicesDetails.services) {
					if (service.launchType !== "FARGATE") {
						continue;
					}

					const platformVersion = service.platformVersion || "";
					const isCompliant = isLatestVersion(platformVersion);

					results.checks.push({
						resourceName: service.serviceName || "Unknown Service",
						resourceArn: service.serviceArn,
						status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: isCompliant
							? undefined
							: `Service is not running on the latest Fargate platform version. Current version: ${platformVersion}`
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: `Cluster: ${cluster}`,
					status: ComplianceStatus.ERROR,
					message: `Error checking services: ${error instanceof Error ? error.message : String(error)}`
				});
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
	const results = await checkEcsFargatePlatformVersion(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECS Fargate services should run on the latest Fargate platform version",
	description:
		"ECS Fargate services must run on the latest platform version (Linux 1.4.0 or Windows 1.0.0) to ensure security updates.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.10",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEcsFargatePlatformVersion,
	serviceName: "Amazon Elastic Container Registry",
	shortServiceName: "ecr"
} satisfies RuntimeTest;
