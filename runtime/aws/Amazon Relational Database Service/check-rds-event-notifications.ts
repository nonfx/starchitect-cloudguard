import {
	RDSClient,
	DescribeEventSubscriptionsCommand,
	DescribeDBInstancesCommand
} from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

const REQUIRED_CATEGORIES = ["maintenance", "configuration change", "failure"];

interface EventSubscriptionInfo {
	sourceType: string;
	isEnabled: boolean;
	hasRequiredCategories: boolean;
	sourceIds?: string[];
}

async function checkRdsEventNotifications(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all event subscriptions
		const response = await client.send(new DescribeEventSubscriptionsCommand({}));

		if (!response.EventSubscriptionsList || response.EventSubscriptionsList.length === 0) {
			results.checks.push({
				resourceName: "RDS Event Subscriptions",
				status: ComplianceStatus.FAIL,
				message: "No RDS event subscriptions found"
			});
			return results;
		}

		// Map to store cluster and instance subscriptions
		const subscriptionMap = new Map<string, EventSubscriptionInfo>();

		// Process all subscriptions
		for (const subscription of response.EventSubscriptionsList) {
			if (!subscription.CustSubscriptionId) {
				continue;
			}

			const info: EventSubscriptionInfo = {
				sourceType: subscription.SourceType || "",
				isEnabled: subscription.Enabled === true,
				hasRequiredCategories: REQUIRED_CATEGORIES.every(cat =>
					subscription.EventCategoriesList?.includes(cat)
				),
				sourceIds: subscription.SourceIdsList
			};

			subscriptionMap.set(subscription.CustSubscriptionId, info);
		}

		// Get all DB instances
		const instancesResponse = await client.send(new DescribeDBInstancesCommand({}));
		if (!instancesResponse.DBInstances) {
			results.checks.push({
				resourceName: "RDS Instances",
				status: ComplianceStatus.ERROR,
				message: "Unable to retrieve RDS instances"
			});
			return results;
		}

		// Check each instance
		for (const instance of instancesResponse.DBInstances) {
			if (!instance.DBInstanceIdentifier || !instance.DBInstanceArn) {
				continue;
			}

			let isCompliant = false;
			const message: string[] = [];

			// First check if instance is part of a cluster with notifications
			if (instance.DBClusterIdentifier) {
				// Check cluster-level subscriptions
				const hasClusterSubscription = Array.from(subscriptionMap.values()).some(
					sub =>
						sub.sourceType === "db-cluster" &&
						sub.isEnabled &&
						sub.hasRequiredCategories &&
						(!sub.sourceIds?.length || sub.sourceIds.includes(instance.DBClusterIdentifier!))
				);

				if (hasClusterSubscription) {
					isCompliant = true;
				} else {
					message.push("No compliant cluster-level event subscription found");
				}
			}

			// If not compliant via cluster, check instance-level subscriptions
			if (!isCompliant) {
				const hasInstanceSubscription = Array.from(subscriptionMap.values()).some(
					sub =>
						sub.sourceType === "db-instance" &&
						sub.isEnabled &&
						sub.hasRequiredCategories &&
						(!sub.sourceIds?.length || sub.sourceIds.includes(instance.DBInstanceIdentifier!))
				);

				if (hasInstanceSubscription) {
					isCompliant = true;
				} else {
					message.push("No compliant instance-level event subscription found");
				}
			}

			results.checks.push({
				resourceName: instance.DBInstanceIdentifier,
				resourceArn: instance.DBInstanceArn,
				status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isCompliant ? undefined : message.join("; ")
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
	const results = await checkRdsEventNotifications(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"RDS event notification subscriptions should be configured for critical database instance events",
	description:
		"RDS event notification subscriptions must be configured to monitor critical database instance events for maintenance, configuration changes, and failures. This can be configured at either the cluster level for RDS instances in a cluster, or at the individual instance level.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.20",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsEventNotifications
} satisfies RuntimeTest;
