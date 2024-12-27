import { RDSClient, DescribeEventSubscriptionsCommand } from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkRdsSecurityGroupEventNotifications(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new RDSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all event subscriptions
		const command = new DescribeEventSubscriptionsCommand({});
		const response = await client.send(command);

		if (!response.EventSubscriptionsList || response.EventSubscriptionsList.length === 0) {
			results.checks.push({
				resourceName: "RDS Event Subscriptions",
				status: ComplianceStatus.FAIL,
				message: "No RDS event subscriptions found"
			});
			return results;
		}

		// Check if any subscription monitors security group events
		const securityGroupSubscriptions = response.EventSubscriptionsList.filter(
			sub => sub.SourceType === "db-security-group"
		);

		if (securityGroupSubscriptions.length === 0) {
			results.checks.push({
				resourceName: "RDS Event Subscriptions",
				status: ComplianceStatus.FAIL,
				message: "No event subscriptions configured for database security group events"
			});
			return results;
		}

		// Check each security group subscription
		for (const subscription of securityGroupSubscriptions) {
			if (!subscription.CustSubscriptionId || !subscription.EventSubscriptionArn) {
				results.checks.push({
					resourceName: "Unknown Subscription",
					status: ComplianceStatus.ERROR,
					message: "Subscription found without ID or ARN"
				});
				continue;
			}

			// Check if subscription is properly configured
			const isValid =
				subscription.Enabled && // Must be enabled
				subscription.SnsTopicArn && // Must have SNS topic
				(!subscription.SourceIdsList?.length || subscription.SourceIdsList.some(id => id)) && // Empty or valid source IDs
				(!subscription.EventCategoriesList?.length ||
					subscription.EventCategoriesList.some(cat => cat)); // Empty or valid categories

			const issues = [];
			if (!subscription.Enabled) {
				issues.push("subscription is disabled");
			}
			if (!subscription.SnsTopicArn) {
				issues.push("no SNS topic configured");
			}
			if (subscription.SourceIdsList?.length && !subscription.SourceIdsList.some(id => id)) {
				issues.push("invalid source IDs");
			}
			if (
				subscription.EventCategoriesList?.length &&
				!subscription.EventCategoriesList.some(cat => cat)
			) {
				issues.push("invalid event categories");
			}

			results.checks.push({
				resourceName: subscription.CustSubscriptionId,
				resourceArn: subscription.EventSubscriptionArn,
				status: isValid ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isValid
					? undefined
					: `Security group event subscription issues: ${issues.join(", ")}`
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "RDS Event Subscriptions",
			status: ComplianceStatus.ERROR,
			message: `Error checking event subscriptions: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsSecurityGroupEventNotifications(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"An RDS event notifications subscription should be configured for critical database security group events",
	description:
		"This control checks whether an RDS event subscription exists for security group events to monitor critical database security group changes.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.22",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsSecurityGroupEventNotifications
} satisfies RuntimeTest;
