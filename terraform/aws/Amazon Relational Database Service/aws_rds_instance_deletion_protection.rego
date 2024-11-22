package rules.rds_instance_deletion_protection

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.8",
	"title": "RDS DB instances should have deletion protection enabled",
	"description": "This control checks if RDS DB instances have deletion protection enabled to prevent accidental or unauthorized database deletion.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.8"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

aws_db_instances = fugue.resources("aws_db_instance")

# Helper function to check if deletion protection is enabled
is_deletion_protected(instance) {
	instance.deletion_protection == true
}

# Allow instances with deletion protection enabled
policy[p] {
	instance := aws_db_instances[_]
	is_deletion_protected(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances without deletion protection
policy[p] {
	instance := aws_db_instances[_]
	not is_deletion_protected(instance)
	p = fugue.deny_resource_with_message(instance, "RDS DB instance does not have deletion protection enabled")
}
