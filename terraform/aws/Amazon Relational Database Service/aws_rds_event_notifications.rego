package rules.rds_event_notifications

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.19",
	"title": "Existing RDS event notification subscriptions should be configured for critical cluster events",
	"description": "This control checks whether RDS event subscriptions are configured to monitor critical cluster events.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.19"]}, "severity": "Low", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

event_subscriptions = fugue.resources("aws_db_event_subscription")

required_categories = ["maintenance", "failure"]

# Check if subscription has all required categories
has_required_categories(subscription) {
	categories := {category | category := subscription.event_categories[_]}
	required := {category | category := required_categories[_]}
	count(required - categories) == 0
}

# Check if subscription is properly configured
is_valid_subscription(subscription) {
	subscription.enabled == true
	subscription.source_type == "db-cluster"
	subscription.sns_topic != null
	has_required_categories(subscription)
}

# Allow if no subscriptions exist
policy[p] {
	count(event_subscriptions) == 0
	p = fugue.allow_resource("aws_db_event_subscription")
}

# Allow properly configured subscriptions
policy[p] {
	subscription := event_subscriptions[_]
	is_valid_subscription(subscription)
	p = fugue.allow_resource(subscription)
}

# Deny improperly configured subscriptions
policy[p] {
	subscription := event_subscriptions[_]
	not is_valid_subscription(subscription)
	p = fugue.deny_resource_with_message(subscription, "RDS event subscription must be enabled and include all critical cluster events (maintenance and failure)")
}
