package rules.rds_instances_public_access

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.2",
	"title": "RDS DB Instances should prohibit public access",
	"description": "RDS DB instances must prohibit public access by ensuring the PubliclyAccessible configuration is disabled for security.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.2"]}, "severity": "Critical", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all RDS instances
rds_instances = fugue.resources("aws_db_instance")

# Helper function to check if instance is publicly accessible
is_public(instance) {
	instance.publicly_accessible == true
}

# Allow RDS instances that are not publicly accessible
policy[p] {
	instance := rds_instances[_]
	not is_public(instance)
	p = fugue.allow_resource(instance)
}

# Deny RDS instances that are publicly accessible
policy[p] {
	instance := rds_instances[_]
	is_public(instance)
	p = fugue.deny_resource_with_message(instance, "RDS DB instance should not be publicly accessible")
}
