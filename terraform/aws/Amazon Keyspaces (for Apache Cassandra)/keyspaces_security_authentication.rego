package rules.keyspaces_security_authentication

import data.fugue

as_array(x) = [x] {
	not is_array(x)
}

__rego__metadoc__ := {
	"id": "DSS05.04.5",
	"title": "Ensure Keyspace Security is Configured - authentication",
	"description": "In order to access Amazon Keyspaces the user is required to set specific networking parameters and security measurements without these extra steps they will not be able to access it. Users are required to create or select a virtual private cloud (VPC) and define their inbound and outbound rules accordingly",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_8.1"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

keyspaces_tables := fugue.resources("aws_keyspaces_table")

vpc_endpoints := fugue.resources("aws_vpc_endpoint")

vpc_security_groups := fugue.resources("aws_security_group")

has_vpc_endpoint(table) {
	count(vpc_endpoints) > 0
}

has_vpc_security_group(endpoint) {
	count(endpoint.security_group_ids) > 0
}

has_ingress_rules(sg) {
	count(sg.ingress) > 0
}

has_egress_rules(sg) {
	count(sg.egress) > 0
}

policy[p] {
	table := keyspaces_tables[_]
	has_vpc_endpoint(table)
	endpoint := vpc_endpoints[_]
	has_vpc_security_group(endpoint)
	sg := vpc_security_groups[_]
	has_ingress_rules(sg)
	has_egress_rules(sg)
	p = fugue.allow_resource(table)
}

policy[p] {
	table := keyspaces_tables[_]
	not has_vpc_endpoint(table)
	msg := sprintf("Keyspaces table '%s' does not have an associated VPC endpoint", [table.table_name])
	p = fugue.deny_resource_with_message(table, msg)
}

policy[p] {
	table := keyspaces_tables[_]
	has_vpc_endpoint(table)
	endpoint := vpc_endpoints[_]
	not has_vpc_security_group(endpoint)
	msg := sprintf("VPC endpoint associated with Keyspaces table '%s' does not have a security group attached", [table.table_name])
	p = fugue.deny_resource_with_message(table, msg)
}

policy[p] {
	table := keyspaces_tables[_]
	has_vpc_endpoint(table)
	endpoint := vpc_endpoints[_]
	has_vpc_security_group(endpoint)
	sg := vpc_security_groups[_]
	not has_ingress_rules(sg)
	msg := sprintf("VPC security group associated with Keyspaces table '%s' does not have ingress rules defined", [table.table_name])
	p = fugue.deny_resource_with_message(table, msg)
}

policy[p] {
	table := keyspaces_tables[_]
	has_vpc_endpoint(table)
	endpoint := vpc_endpoints[_]
	has_vpc_security_group(endpoint)
	sg := vpc_security_groups[_]
	not has_egress_rules(sg)
	msg := sprintf("VPC security group associated with Keyspaces table '%s' does not have egress rules defined", [table.table_name])
	p = fugue.deny_resource_with_message(table, msg)
}
