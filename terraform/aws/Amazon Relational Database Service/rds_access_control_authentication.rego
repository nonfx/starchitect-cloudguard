package rules.rds_access_control_authentication

import data.fugue

__rego__metadoc__ := {
	"id": "3.7",
	"title": "Ensure to Implement Access Control and Authentication",
	"description": "Users should select whether they like to enable authentication. If they want to authenticate a password would be required, which would only allow the authorized person to access the database. Defining access control allows specific workers in a business access to the database",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_3.7"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

rds_instances := fugue.resources("aws_db_instance")

is_compliant(instance) {
	instance.publicly_accessible == false
	instance.iam_database_authentication_enabled == true
}

policy[p] {
	instance := rds_instances[_]
	is_compliant(instance)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := rds_instances[_]
	not is_compliant(instance)
	msg := sprintf("RDS instance '%s' does not have proper access control and authentication. Ensure public accessibility is disabled and IAM database authentication is enabled.", [instance.id])
	p = fugue.deny_resource_with_message(instance, msg)
}
