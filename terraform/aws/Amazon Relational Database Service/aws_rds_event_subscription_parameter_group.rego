package rules.rds_event_subscription_parameter_group

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.21",
	"title": "An RDS event notifications subscription should be configured for critical database parameter group events",
	"description": "This control checks whether an RDS event subscription exists that monitors parameter group configuration changes. Event notifications using Amazon SNS help in rapid response to changes.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.21"]}, "severity": "Low", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all RDS event subscriptions
event_subscriptions = fugue.resources("aws_db_event_subscription")

# Helper to check if subscription monitors parameter group events
is_parameter_group_monitored(subscription) {
	# Check if source type includes parameter groups
	subscription.source_type == "db-parameter-group"

	# Check if event categories include configuration change
	subscription.event_categories[_] == "configuration change"

	# Ensure SNS topic is configured
	subscription.sns_topic != null
}

# Allow if valid subscription exists
policy[p] {
	subscription := event_subscriptions[_]
	is_parameter_group_monitored(subscription)
	p = fugue.allow_resource(subscription)
}

# Deny if subscription exists but doesn't monitor parameter groups correctly
policy[p] {
	subscription := event_subscriptions[_]
	not is_parameter_group_monitored(subscription)
	p = fugue.deny_resource_with_message(subscription, "RDS event subscription must monitor db-parameter-group configuration changes")
}

# Allow if no subscriptions exist (per AWS documentation)
policy[p] {
	count(event_subscriptions) == 0
	p = fugue.allow_resource("aws_db_event_subscription")
}
