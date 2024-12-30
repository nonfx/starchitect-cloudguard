import {
	RDSClient,
	DescribeEventSubscriptionsCommand,
	DescribeDBParameterGroupsCommand
} from "@aws-sdk/client-rds";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkRdsEventSubscriptionParameterGroup(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
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

		// Find valid parameter group subscriptions
		const validSubscriptions = subscriptions.filter(
			sub =>
				sub.SourceType === "db-parameter-group" &&
				(sub.EventCategoriesList?.includes("configuration change") || !sub.EventCategoriesList) &&
				sub.Enabled === true &&
				sub.SnsTopicArn
		);

		// Get all parameter groups
		const paramGroupsResponse = await client.send(new DescribeDBParameterGroupsCommand({}));
		const parameterGroups = paramGroupsResponse.DBParameterGroups || [];

		if (parameterGroups.length === 0) {
			results.checks.push({
				resourceName: "RDS Parameter Groups",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No RDS parameter groups found"
			});
			return results;
		}

		// Check each parameter group
		for (const paramGroup of parameterGroups) {
			if (!paramGroup.DBParameterGroupName) continue;

			// Check if this parameter group is monitored by any subscription
			const isMonitored = validSubscriptions.some(sub => {
				// If subscription has no source IDs, it applies to all parameter groups
				if (!sub.SourceIdsList || sub.SourceIdsList.length === 0) {
					return true;
				}
				// Otherwise check if this parameter group is in the source IDs
				return sub.SourceIdsList.includes(paramGroup.DBParameterGroupName!);
			});

			results.checks.push({
				resourceName: paramGroup.DBParameterGroupName,
				resourceArn: paramGroup.DBParameterGroupArn,
				status: isMonitored ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isMonitored
					? undefined
					: "Parameter group changes are not monitored by any event subscription"
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

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkRdsEventSubscriptionParameterGroup(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"An RDS event notifications subscription should be configured for critical database parameter group events",
	description:
		"This control checks whether all RDS parameter groups are monitored by event subscriptions for configuration changes. Event notifications using Amazon SNS help in rapid response to changes. A subscription can monitor all parameter groups if no source IDs are specified, or specific parameter groups listed in its source IDs.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.21",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkRdsEventSubscriptionParameterGroup,
	serviceName: "Amazon Relational Database Service"
} satisfies RuntimeTest;
