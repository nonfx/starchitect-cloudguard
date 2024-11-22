# Package declaration for the rule
package rules.rds_no_public_access

# Import the fugue library
import data.fugue

__rego__metadoc__ := {
	"id": "2.3.3",
	"title": "Ensure that public access is not given to RDS Instance",
	"description": "Ensure and verify that RDS database instances provisioned in your AWS account do restrict unauthorized access in order to minimize security risks. To restrict access to any publicly accessible RDS database instance, you must disable the database Publicly Accessible flag and update the VPC security group associated with the instance.",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_2.3.3"]}, "severity": "Low", "author": "Starchitect Agent"},
}

# Set resource type to MULTIPLE for advanced rule
resource_type := "MULTIPLE"

# Query for all RDS instances
rds_instances = fugue.resources("aws_db_instance")

# Auxiliary function to check if public access is disabled
is_public_access_disabled(resource) {
	resource_has_property(resource)
	resource.publicly_accessible == false
}

is_public_access_disabled(resource) {
	# Pass if the publicly_accessible property does not exist
	not resource_has_property(resource)
}

policy[p] {
	resource = rds_instances[_]
	is_public_access_disabled(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = rds_instances[_]
	not is_public_access_disabled(resource)
	p = fugue.deny_resource_with_message(resource, "RDS instance must not be publicly accessible")
}

resource_has_property(resource) {
	_ = resource.publicly_accessible
}
