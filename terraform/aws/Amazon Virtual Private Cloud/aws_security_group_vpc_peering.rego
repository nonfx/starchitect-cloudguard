package rules.aws_security_group_vpc_peering

import data.fugue

resource_type := "MULTIPLE"

__rego__metadoc__ := {
	"author": "chandra@nonfx.com", "custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_5.5"]},
		"severity": "Low",
	},
	"id": "5.5",
	"title": "Ensure routing tables for VPC peering are \"least access\"",
	"description": "Once a VPC peering connection is established, routing tables must be updated to establish any connections between the peered VPCs. These routes can be as specific as desired - even peering a VPC to only a single host on the other side of the connection.",
}

resource_type := "MULTIPLE"

routing_tables := fugue.resources("aws_route_table")

peering_connections := fugue.resources("aws_vpc_peering_connection")

# Function to check if the route is for a peering connection and if it is specific
is_least_access_route(route) {
	route.gateway_id != null
	count(split(route.cidr_block, "/")) > 1
	suffix := split(route.cidr_block, "/")[1]
	suffix != "0"
	suffix != "32"
}

policy[p] {
	peering_connections[_]
	route_table := routing_tables[_]
	route := route_table.route[_]
	is_least_access_route(route)
	p = fugue.allow_resource(route_table)
}

policy[p] {
	peering_connections[_]
	route_table := routing_tables[_]
	route := route_table.route[_]
	not is_least_access_route(route)
	p = fugue.deny_resource_with_message(route_table, "Routing table contains non-least access routes for VPC peering.")
}
