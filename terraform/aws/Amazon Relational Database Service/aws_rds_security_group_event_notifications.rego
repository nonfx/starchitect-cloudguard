package rules.rds_security_group_event_notifications

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.22",
	"title": "An RDS event notifications subscription should be configured for critical database security group events",
	"description": "This control checks whether an RDS event subscription exists for security group events to monitor critical database security group changes.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.22"]}, "severity": "Low", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all RDS event subscriptions
event_subscriptions = fugue.resources("aws_db_event_subscription")

# Helper function to check if security group events are monitored
has_security_group_monitoring(subscription) {
	subscription.source_type == "db-security-group"
}

# Allow if at least one subscription monitors security group events
policy[p] {
	subscription := event_subscriptions[_]
	has_security_group_monitoring(subscription)
	p = fugue.allow_resource(subscription)
}

# Deny if no subscription monitors security group events
policy[p] {
	count(event_subscriptions) > 0
	not any_security_group_monitoring
	p = fugue.missing_resource_with_message(
		"aws_db_event_subscription",
		"No RDS event subscription is configured to monitor database security group events",
	)
}

# Helper rule to check if any subscription monitors security group events
any_security_group_monitoring {
	subscription := event_subscriptions[_]
	has_security_group_monitoring(subscription)
}
