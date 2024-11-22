package rules.dms_replication_instance_auto_minor_version_upgrade

import data.fugue

__rego__metadoc__ := {
	"id": "DMS.6",
	"title": "DMS replication instances should have automatic minor version upgrade enabled",
	"description": "DMS replication instances must have automatic minor version upgrade enabled for security patches and improvements.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_DMS.6"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

dms_replication_instances = fugue.resources("aws_dms_replication_instance")

# Helper function to check if auto minor version upgrade is enabled
is_auto_minor_version_upgrade_enabled(instance) {
	instance.auto_minor_version_upgrade == true
}

# Policy rule for allowing instances with auto minor version upgrade enabled
policy[p] {
	instance := dms_replication_instances[_]
	is_auto_minor_version_upgrade_enabled(instance)
	p = fugue.allow_resource(instance)
}

# Policy rule for denying instances without auto minor version upgrade enabled
policy[p] {
	instance := dms_replication_instances[_]
	not is_auto_minor_version_upgrade_enabled(instance)
	p = fugue.deny_resource_with_message(
		instance,
		"DMS replication instance must have automatic minor version upgrade enabled",
	)
}
