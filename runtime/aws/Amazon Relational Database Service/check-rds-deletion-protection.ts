import {
	RDSClient,
	DescribeDBInstancesCommand,
	DescribeDBClustersCommand
} from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkRdsDeletionProtection(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// First check clusters
		const clusterResponse = await client.send(new DescribeDBClustersCommand({}));
		const clusters = clusterResponse.DBClusters || [];

		// Then check instances
		let marker: string | undefined;
		let instanceFound = false;
		let instances: any[] = [];

		do {
			const command = new DescribeDBInstancesCommand({
				Marker: marker
			});

			const response = await client.send(command);
			if (response.DBInstances) {
				instances = instances.concat(response.DBInstances);
				instanceFound = true;
			}
			marker = response.Marker;
		} while (marker);

		// If no resources found
		if (clusters.length === 0 && !instanceFound) {
			results.checks = [
				{
					resourceName: "No RDS Resources",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No RDS clusters or instances found in the region"
				}
			];
			return results;
		}

		// Check each cluster
		for (const cluster of clusters) {
			if (!cluster.DBClusterIdentifier || !cluster.DBClusterArn) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without identifier or ARN"
				});
				continue;
			}

			// Find associated instances
			const clusterInstances = instances.filter(
				instance => instance.DBClusterIdentifier === cluster.DBClusterIdentifier
			);

			// Check if either cluster or any of its instances have deletion protection
			const clusterProtected = cluster.DeletionProtection;
			const instanceProtected = clusterInstances.some(instance => instance.DeletionProtection);
			const isProtected = clusterProtected || instanceProtected;

			results.checks.push({
				resourceName: cluster.DBClusterIdentifier,
				resourceArn: cluster.DBClusterArn,
				status: isProtected ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isProtected
					? undefined
					: "Neither RDS cluster nor its instances have deletion protection enabled"
			});
		}

		// Check standalone instances (not part of any cluster)
		for (const instance of instances) {
			if (!instance.DBClusterIdentifier) {
				// Only check instances not part of a cluster
				if (!instance.DBInstanceIdentifier || !instance.DBInstanceArn) {
					results.checks.push({
						resourceName: "Unknown Instance",
						status: ComplianceStatus.ERROR,
						message: "Instance found without identifier or ARN"
					});
					continue;
				}

				results.checks.push({
					resourceName: instance.DBInstanceIdentifier,
					resourceArn: instance.DBInstanceArn,
					status: instance.DeletionProtection ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: instance.DeletionProtection
						? undefined
						: "RDS instance does not have deletion protection enabled"
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "RDS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking RDS resources: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsDeletionProtection(region);
	printSummary(generateSummary(results));
}

export default {
	title: "RDS DB instances and clusters should have deletion protection enabled",
	description:
		"This control checks if RDS DB instances and clusters have deletion protection enabled at either the cluster or instance level to prevent accidental or unauthorized database deletion.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.8",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsDeletionProtection
} satisfies RuntimeTest;
