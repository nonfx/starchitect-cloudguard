package rules.aws_keyspaces_vpc_endpoint_security

import data.fugue

__rego__metadoc__ := {
	"id": "8.1",
	"title": "Ensure Keyspace Security is Configured with VPC Endpoints",
	"description": "Amazon Keyspaces should be accessed via VPC endpoints to ensure traffic does not leave the Amazon network, enhancing security and reducing latency. This setup uses Interface VPC Endpoints powered by AWS PrivateLink, which allows direct connection from a VPC to Amazon Keyspaces without exposure to the public internet.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_8.1"]},
		"severity": "High",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

vpc_endpoints := fugue.resources("aws_vpc_endpoint")

keyspaces := fugue.resources("aws_keyspaces_keyspace")

keyspaces_access_via_endpoint(endpoint) {
	endpoint.service_name == "cassandra.amazonaws.com"
	endpoint.vpc_endpoint_type == "Interface"
	count(keyspaces) > 0
}

policy[p] {
	count(keyspaces) > 0
	keyspace := keyspaces[_]
	count(vpc_endpoints) > 0
	endpoint := vpc_endpoints[_]
	keyspaces_access_via_endpoint(endpoint)
	p = fugue.allow_resource(keyspace)
}

policy[p] {
	count(keyspaces) > 0
	count(vpc_endpoints) > 0
	endpoint := vpc_endpoints[_]
	not keyspaces_access_via_endpoint(endpoint)
	msg := sprintf("VPC Endpoint '%s' is not configured for Amazon Keyspaces access.", [endpoint.id])
	p = fugue.deny_resource_with_message(endpoint, msg)
}

policy[p] {
	count(keyspaces) > 0
	keyspace := keyspaces[_]
	not count(vpc_endpoints) > 0
	msg := sprintf("VPC Endpoint does not exist for Amazon Keyspaces", [])
	p = fugue.deny_resource_with_message(keyspace, msg)
}
