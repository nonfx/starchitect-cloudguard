package rules.rds_multi_az_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.5",
	"title": "RDS DB instances should be configured with multiple Availability Zones",
	"description": "RDS DB instances must be configured with multiple Availability Zones for high availability and automated failover capabilities. Multi-AZ deployments enhance availability during system upgrades, DB instance failure, and Availability Zone disruption.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.5"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all RDS DB instances
db_instances = fugue.resources("aws_db_instance")

# Helper to check if Multi-AZ is enabled
is_multi_az_enabled(instance) {
	instance.multi_az == true
}

# Allow if Multi-AZ is enabled
policy[p] {
	instance := db_instances[_]
	is_multi_az_enabled(instance)
	p = fugue.allow_resource(instance)
}

# Deny if Multi-AZ is not enabled
policy[p] {
	instance := db_instances[_]
	not is_multi_az_enabled(instance)
	p = fugue.deny_resource_with_message(instance, "RDS DB instance must be configured with multiple Availability Zones for high availability")
}
