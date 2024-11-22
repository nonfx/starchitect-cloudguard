package rules.documentdb_subnet_group_acls

import data.fugue

__rego__metadoc__ := {
	"id": "CIS_AWS_DB_7.1_7.2",
	"title": "Ensure DocumentDB clusters are in VPCs with proper network ACLs",
	"description": "This rule ensures that DocumentDB clusters are associated with subnets that are part of a VPC and have network ACLs configured. This helps in isolating DocumentDB instances within a secure Virtual Private Cloud (VPC) and controlling inbound and outbound traffic.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_7.1", "CIS-AWS-Database-Services-Benchmark_v1.0.0_7.2"]}, "severity": "High", "author": "Starchitect Agent"},
}

# Define the resource type due to handling multiple AWS resources.
resource_type := "MULTIPLE"

# Fetch necessary resources.
docdb_clusters = fugue.resources("aws_docdb_cluster")

subnets = fugue.resources("aws_subnet")

docdb_subnet_groups = fugue.resources("aws_docdb_subnet_group")

network_acls = fugue.resources("aws_network_acl")

network_acl_associations = fugue.resources("aws_network_acl_association")

vpcs = fugue.resources("aws_vpc")

# Function to find a matching subnet for the DocumentDB cluster's subnet group.
find_matching_subnet(db_cluster) = subnet {
	subnet_group = docdb_subnet_groups[_]
	subnet_group.name == db_cluster.db_subnet_group_name
	subnet_id = subnet_group.subnet_ids[_]
	subnet = subnets[subnet_id] # Return the subnet
}

# Function to check if the subnet is associated with a VPC.
is_subnet_in_vpc(subnet) {
	vpc = vpcs[_]
	subnet.vpc_id == vpc.id
}

# Function to validate network ACL association with the subnet.
is_subnet_part_of_any_acl(subnet) {
	network_acl = network_acls[_]
	network_acl.vpc_id == subnet.vpc_id
	acl_association = network_acl_associations[_]
	acl_association.network_acl_id == network_acl.id
	acl_association.subnet_id == subnet.id
}

# Main policy rule evaluation using a single block for PASS and individual blocks for each FAIL case.
policy[result] {
	db_cluster = docdb_clusters[_]
	subnet = find_matching_subnet(db_cluster)

	# Check both conditions now using the subnet result from find_matching_subnet
	is_subnet_in_vpc(subnet)
	is_subnet_part_of_any_acl(subnet)

	# If all checks pass, allow the resource
	result = fugue.allow_resource(db_cluster)
}

policy[result] {
	db_cluster = docdb_clusters[_]
	subnet = find_matching_subnet(db_cluster)

	# Check if subnet is not in a VPC
	not is_subnet_in_vpc(subnet)

	result = fugue.deny_resource_with_message(db_cluster, "The associated subnet for the DocumentDB cluster is not in any VPC.")
}

policy[result] {
	db_cluster = docdb_clusters[_]
	subnet = find_matching_subnet(db_cluster)

	# Check if subnet is not part of any network ACL
	not is_subnet_part_of_any_acl(subnet)

	result = fugue.deny_resource_with_message(db_cluster, "The associated subnet for the DocumentDB cluster is not part of any network ACL association.")
}

policy[result] {
	db_cluster = docdb_clusters[_]
	not find_matching_subnet(db_cluster)
	result = fugue.deny_resource_with_message(db_cluster, "The DocumentDB cluster does not have an associated subnet group.")
}
