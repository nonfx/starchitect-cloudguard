package rules.dms_replication_instances_not_public

import data.fugue

__rego__metadoc__ := {
	"id": "DMS.1",
	"title": "Database Migration Service replication instances should not be public",
	"description": "AWS DMS replication instances must not be publicly accessible to maintain security and prevent unauthorized access to database migration resources.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_DMS.1"]}, "severity": "Critical", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

dms_replication_instances = fugue.resources("aws_dms_replication_instance")

# Helper function to check if instance is public
is_public(instance) {
	instance.publicly_accessible == true
}

# Policy rule for private instances
policy[p] {
	instance := dms_replication_instances[_]
	not is_public(instance)
	p = fugue.allow_resource(instance)
}

# Policy rule for public instances
policy[p] {
	instance := dms_replication_instances[_]
	is_public(instance)
	p = fugue.deny_resource_with_message(
		instance,
		"DMS replication instance should not be publicly accessible",
	)
}
