package rules.aws_keyspace_audit_logging

import data.fugue

__rego__metadoc__ := {
	"id": "8.1",
	"title": "Ensure Keyspace Security is Configured - audit logging",
	"description": "In order to access Amazon Keyspaces the user is required to set specific networking parameters and security measurements without these extra steps they will not be able to access it. Users are required to create or select a virtual private cloud (VPC) and define their inbound and outbound rules accordingly",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_8.1"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudtrails := fugue.resources("aws_cloudtrail")

keyspaces := fugue.resources("aws_keyspaces_keyspace")

has_keyspace_logging_enabled(trail) {
	trail.event_selector[_].data_resource[_].type == "AWS::Cassandra::Table"
	trail.event_selector[_].include_management_events
}

policy[p] {
	keyspace := keyspaces[_]
	trail := cloudtrails[_]
	has_keyspace_logging_enabled(trail)
	p = fugue.allow_resource(keyspace)
}

policy[p] {
	keyspace := keyspaces[_]
	trail := cloudtrails[_]
	not has_keyspace_logging_enabled(trail)
	msg := sprintf("Keyspace '%s' does not have audit logging enabled", [keyspace.name])
	p = fugue.deny_resource_with_message(keyspace, msg)
}

policy[p] {
	keyspace := keyspaces[_]
	count(cloudtrails) == 0
	msg := sprintf("Keyspace '%s' does not have audit logging configured using cloudtrail", [keyspace.name])
	p = fugue.deny_resource_with_message(keyspace, msg)
}
