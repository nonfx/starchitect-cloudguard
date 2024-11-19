# Package declaration for the rule
package rules.rds_auto_minor_version_upgrade

# Import the fugue library
import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "2.3.2",
	"title": "Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances",
	"description": "Ensure that RDS database instances have the Auto Minor Version Upgrade flag enabled in order to receive automatically minor engine upgrades during the specified maintenance window. So, RDS instances can get the new features, bug fixes, and security patches for their database engines.",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_2.3.2"]}, "severity": "Low", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

# Set resource type to MULTIPLE for advanced rule
resource_type := "MULTIPLE"

# Query for all RDS instances
rds_instances = fugue.resources("aws_db_instance")

# Auxiliary function to check if Auto Minor Version Upgrade is enabled
is_auto_upgrade_enabled(resource) {
	resource.auto_minor_version_upgrade == true
}

# Policy rule that holds the set of judgements
policy[p] {
	resource = rds_instances[_]
	is_auto_upgrade_enabled(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = rds_instances[_]
	not is_auto_upgrade_enabled(resource)
	p = fugue.deny_resource_with_message(resource, "RDS instance must have Auto Minor Version Upgrade feature enabled")
}
