package rules.rds_instance_copy_tags_to_snapshots

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.17",
	"title": "RDS DB instances should be configured to copy tags to snapshots",
	"description": "This control checks whether RDS DB instances are configured to automatically copy tags to snapshots when they are created.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.17"]}, "severity": "Low", "author": "Starchitect Agent"},
}

# Define the resource type we're evaluating
resource_type := "MULTIPLE"

# Get all RDS instances
rds_instances = fugue.resources("aws_db_instance")

# Helper function to check if copy tags to snapshots is enabled
is_copy_tags_enabled(resource) {
	resource.copy_tags_to_snapshot == true
}

# Allow RDS instances that have copy_tags_to_snapshot enabled
policy[p] {
	resource := rds_instances[_]
	is_copy_tags_enabled(resource)
	p = fugue.allow_resource(resource)
}

# Deny RDS instances that don't have copy_tags_to_snapshot enabled
policy[p] {
	resource := rds_instances[_]
	not is_copy_tags_enabled(resource)
	p = fugue.deny_resource_with_message(
		resource,
		"RDS DB instance must have copy_tags_to_snapshot enabled to ensure proper resource tracking and management",
	)
}
