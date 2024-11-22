package rules.ecs_no_public_ip

import data.fugue

__rego__metadoc__ := {
	"id": "ECS.2",
	"title": "ECS services should not have public IP addresses assigned to them automatically",
	"description": "This control checks if ECS services are configured to automatically assign public IP addresses. Services with automatic public IP assignment are accessible from the internet, which may pose security risks.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all ECS services
ecs_services = fugue.resources("aws_ecs_service")

# Helper function to check if public IP assignment is disabled
is_public_ip_disabled(service) {
	service.network_configuration[_].assign_public_ip == false
}

# Allow services with public IP assignment disabled
policy[p] {
	service := ecs_services[_]
	is_public_ip_disabled(service)
	p = fugue.allow_resource(service)
}

# Deny services with public IP assignment enabled
policy[p] {
	service := ecs_services[_]
	not is_public_ip_disabled(service)
	p = fugue.deny_resource_with_message(service, "ECS service should not have automatic public IP assignment enabled. Configure network settings to disable public IP assignment.")
}
