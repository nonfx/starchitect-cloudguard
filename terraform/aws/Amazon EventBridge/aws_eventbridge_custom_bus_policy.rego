package rules.eventbridge_custom_bus_policy

import data.fugue

__rego__metadoc__ := {
	"id": "EventBridge.3",
	"title": "EventBridge custom event buses should have a resource-based policy attached",
	"description": "EventBridge custom event buses must have resource-based policies attached to control access and limit permissions effectively.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_EventBridge.3"]}, "severity": "Low", "author": "llmagent"},
}

resource_type := "MULTIPLE"

# Get all EventBridge event buses
event_buses = fugue.resources("aws_cloudwatch_event_bus")

# Get all EventBridge event bus policies
event_bus_policies = fugue.resources("aws_cloudwatch_event_bus_policy")

# Check if event bus has policy attached
has_policy(bus) {
	policy := event_bus_policies[_]
	policy.event_bus_name == bus.name
}

# Allow if event bus has policy attached
policy[p] {
	bus := event_buses[_]
	has_policy(bus)
	p = fugue.allow_resource(bus)
}

# Deny if event bus doesn't have policy attached
policy[p] {
	bus := event_buses[_]
	not has_policy(bus)
	p = fugue.deny_resource_with_message(
		bus,
		sprintf("EventBridge custom event bus '%s' must have a resource-based policy attached", [bus.name]),
	)
}
