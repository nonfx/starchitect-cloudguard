package rules.aws_elasticache_network_security

import data.fugue

__rego__metadoc__ := {
	"id": "5.2",
	"title": "Ensure Network Security is Enabled",
	"description": "Implementing network security for Amazon ElastiCache involves configuring your Virtual Private Cloud (VPC), security groups, and network access controls to control access to your ElastiCache clusters.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_5.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

elasticache_clusters := fugue.resources("aws_elasticache_cluster")

security_groups := fugue.resources("aws_security_group")

nacls := fugue.resources("aws_network_acl")

cluster_in_vpc(cluster) {
	cluster.security_group_ids[_]
}

appropriate_sg(sg) {
	sg.ingress[_]
	sg.egress[_]
}

appropriate_nacl(nacl) {
	nacl.ingress[_]
	nacl.egress[_]
}

policy[p] {
	cluster := elasticache_clusters[_]
	sg := security_groups[_]
	nacl := nacls[_]
	cluster_in_vpc(cluster)
	appropriate_sg(sg)
	appropriate_nacl(nacl)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := elasticache_clusters[_]
	not cluster_in_vpc(cluster)
	p = fugue.deny_resource_with_message(cluster, "ElastiCache cluster is not properly isolated in a VPC.")
}

policy[p] {
	sg := security_groups[_]
	not appropriate_sg(sg)
	p = fugue.deny_resource_with_message(sg, "Security group does not have appropriate ingress or egress rules.")
}

policy[p] {
	nacl := nacls[_]
	not appropriate_nacl(nacl)
	p = fugue.deny_resource_with_message(nacl, "Network ACL does not have appropriate ingress or egress rules.")
}
