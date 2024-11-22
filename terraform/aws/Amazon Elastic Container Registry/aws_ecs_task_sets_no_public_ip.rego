package rules.ecs_task_sets_no_public_ip

import data.fugue

__rego__metadoc__ := {
	"id": "ECS.16",
	"title": "ECS task sets should not automatically assign public IP addresses",
	"description": "ECS task sets should disable automatic public IP address assignment to prevent unauthorized internet access to container applications.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.16"]}, "severity": "High"},
}

resource_type := "MULTIPLE"

# Get all ECS service resources
ecs_services = fugue.resources("aws_ecs_service")

# Helper function to check if public IP assignment is disabled
is_public_ip_disabled(service) {
	service.network_configuration[_].assign_public_ip == false
}

# Allow services that have public IP assignment disabled
policy[p] {
	service := ecs_services[_]
	is_public_ip_disabled(service)
	p = fugue.allow_resource(service)
}

# Deny services that have public IP assignment enabled
policy[p] {
	service := ecs_services[_]
	not is_public_ip_disabled(service)
	p = fugue.deny_resource_with_message(service, "ECS service should not automatically assign public IP addresses")
}
