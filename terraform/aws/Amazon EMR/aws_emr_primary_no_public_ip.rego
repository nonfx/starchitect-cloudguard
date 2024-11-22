package rules.emr_primary_no_public_ip

import data.fugue

__rego__metadoc__ := {
	"id": "EMR.1",
	"title": "Amazon EMR cluster primary nodes should not have public IP addresses",
	"description": "This control checks if EMR cluster primary nodes have public IP addresses. The control fails if public IPs are associated with primary node instances to maintain network security.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EMR.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

emr_clusters := fugue.resources("aws_emr_cluster")

subnets := fugue.resources("aws_subnet")

# Check if cluster's subnet has public IP mapping disabled
is_private_subnet(cluster) {
	subnet := subnets[_]
	cluster.ec2_attributes[_].subnet_id == subnet.id
	not subnet.map_public_ip_on_launch
}

# Allow clusters in private subnets
policy[p] {
	cluster := emr_clusters[_]
	is_private_subnet(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters in public subnets
policy[p] {
	cluster := emr_clusters[_]
	not is_private_subnet(cluster)
	p = fugue.deny_resource_with_message(cluster, "EMR cluster primary node must be in a private subnet without public IP mapping")
}
