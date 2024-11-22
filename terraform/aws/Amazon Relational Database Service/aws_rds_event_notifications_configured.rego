package rules.rds_event_notifications_configured

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.20",
	"title": "RDS event notification subscriptions should be configured for critical database instance events",
	"description": "RDS event notification subscriptions must be configured to monitor critical database instance events for maintenance, configuration changes, and failures.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.20"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all RDS event subscriptions
event_subscriptions = fugue.resources("aws_db_event_subscription")

# Required event categories
required_categories = {
	"maintenance",
	"configuration change",
	"failure",
}

# Helper to check if subscription has required source type
has_db_instance_source(subscription) {
	subscription.source_type == "db-instance"
}

# Helper to check if subscription has all required categories
has_required_categories(subscription) {
	categories := {category | category := subscription.event_categories[_]}
	required_categories & categories == required_categories
}

# Helper to check if subscription is enabled
is_enabled(subscription) {
	subscription.enabled == true
}

# Helper to check all requirements
meets_all_requirements(subscription) {
	has_db_instance_source(subscription)
	has_required_categories(subscription)
	is_enabled(subscription)
}

# Allow if no subscriptions exist (per AWS Security Hub requirements)
policy[p] {
	count(event_subscriptions) == 0
	p = fugue.allow_resource("aws_db_event_subscription")
}

# Allow if subscription meets all requirements
policy[p] {
	count(event_subscriptions) > 0
	subscription := event_subscriptions[_]
	meets_all_requirements(subscription)
	p = fugue.allow_resource(subscription)
}

# Deny if subscription exists but doesn't meet requirements
policy[p] {
	count(event_subscriptions) > 0
	subscription := event_subscriptions[_]
	not meets_all_requirements(subscription)
	p = fugue.deny_resource_with_message(subscription, "RDS event subscription must be enabled, have source type 'db-instance', and include categories: maintenance, configuration change, and failure")
}
