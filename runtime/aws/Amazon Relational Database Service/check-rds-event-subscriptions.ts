import {
	RDSClient,
	DescribeEventSubscriptionsCommand,
	DescribeDBInstancesCommand,
	DescribeDBClustersCommand
} from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const REQUIRED_CATEGORIES = ["maintenance", "failure"];

async function checkRdsEventSubscriptions(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all event subscriptions first
		const subsResponse = await client.send(new DescribeEventSubscriptionsCommand({}));
		const subscriptions = subsResponse.EventSubscriptionsList || [];

		if (subscriptions.length === 0) {
			results.checks.push({
				resourceName: "RDS Event Subscriptions",
				status: ComplianceStatus.FAIL,
				message: "No RDS event subscriptions found"
			});
			return results;
		}

		// Get all DB instances
		const instancesResponse = await client.send(new DescribeDBInstancesCommand({}));
		const instances = instancesResponse.DBInstances || [];

		if (instances.length === 0) {
			results.checks.push({
				resourceName: "RDS Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No RDS instances found"
			});
			return results;
		}

		// Get all clusters for lookup
		const clustersResponse = await client.send(new DescribeDBClustersCommand({}));
		//@todo - figure out what it's meant to be used for
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const clusterMap = new Map(
			(clustersResponse.DBClusters || []).map(c => [c.DBClusterIdentifier!, c])
		);

		// Check each instance
		for (const instance of instances) {
			if (!instance.DBInstanceIdentifier || !instance.DBInstanceArn) continue;

			let isMonitored = false;
			let missingCategories: string[] = [];

			// First check if instance is part of a cluster
			if (instance.DBClusterIdentifier) {
				// Check cluster-level subscriptions first
				for (const sub of subscriptions) {
					if (!sub.Enabled || !sub.SnsTopicArn || sub.SourceType !== "db-cluster") continue;

					const appliesTo =
						!sub.SourceIdsList?.length || sub.SourceIdsList.includes(instance.DBClusterIdentifier);
					if (!appliesTo) continue;

					if (!sub.EventCategoriesList?.length) {
						isMonitored = true;
						missingCategories = [];
						break;
					}

					const subCategories = new Set(sub.EventCategoriesList);
					const missing = REQUIRED_CATEGORIES.filter(cat => !subCategories.has(cat));

					if (missing.length === 0) {
						isMonitored = true;
						missingCategories = [];
						break;
					} else if (missing.length < missingCategories.length || missingCategories.length === 0) {
						missingCategories = missing;
					}
				}
			}

			// If not monitored via cluster, check instance-level subscriptions
			if (!isMonitored) {
				for (const sub of subscriptions) {
					if (!sub.Enabled || !sub.SnsTopicArn || sub.SourceType !== "db-instance") continue;

					const appliesTo =
						!sub.SourceIdsList?.length || sub.SourceIdsList.includes(instance.DBInstanceIdentifier);
					if (!appliesTo) continue;

					if (!sub.EventCategoriesList?.length) {
						isMonitored = true;
						missingCategories = [];
						break;
					}

					const subCategories = new Set(sub.EventCategoriesList);
					const missing = REQUIRED_CATEGORIES.filter(cat => !subCategories.has(cat));

					if (missing.length === 0) {
						isMonitored = true;
						missingCategories = [];
						break;
					} else if (missing.length < missingCategories.length || missingCategories.length === 0) {
						missingCategories = missing;
					}
				}
			}

			results.checks.push({
				resourceName: instance.DBInstanceIdentifier,
				resourceArn: instance.DBInstanceArn,
				status: isMonitored ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isMonitored
					? undefined
					: missingCategories.length
						? `Missing event categories: ${missingCategories.join(", ")}`
						: instance.DBClusterIdentifier
							? "Neither cluster nor instance has an enabled event subscription"
							: "No enabled event subscription found"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "RDS Event Subscriptions",
			status: ComplianceStatus.ERROR,
			message: `Error checking RDS event subscriptions: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsEventSubscriptions(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"RDS event notification subscriptions should be configured for critical cluster and instance events",
	description:
		"This control checks whether all RDS clusters and instances are monitored by event subscriptions for critical events. A subscription can monitor all resources of its type if no source IDs are specified, or specific resources listed in its source IDs. Similarly, if no event categories are specified, the subscription monitors all event types.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.19",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsEventSubscriptions,
	serviceName: "Amazon Relational Database Service",
	shortServiceName: "rds"
} satisfies RuntimeTest;
