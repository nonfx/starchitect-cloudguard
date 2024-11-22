package rules.rds_automated_backups_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.11",
	"title": "RDS instances should have automatic backups enabled",
	"description": "RDS instances must have automated backups enabled with a minimum retention period of 7 days for data recovery and system resilience.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.11"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

rds_instances = fugue.resources("aws_db_instance")

# Helper to check if instance is a read replica
is_read_replica(instance) {
	instance.replicate_source_db != null
}

# Helper to check if backups are properly configured
has_valid_backup_config(instance) {
	not is_read_replica(instance)
	instance.backup_retention_period >= 7
}

# Allow instances with proper backup configuration
policy[p] {
	instance := rds_instances[_]
	has_valid_backup_config(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances without proper backup configuration
policy[p] {
	instance := rds_instances[_]
	not is_read_replica(instance)
	not has_valid_backup_config(instance)
	p = fugue.deny_resource_with_message(instance, "RDS instance must have automated backups enabled with a minimum retention period of 7 days")
}
