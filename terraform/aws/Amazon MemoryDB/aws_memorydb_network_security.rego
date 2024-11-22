package rules.aws_memorydb_network_security

import data.fugue

__rego__metadoc__ := {
	"id": "6.1",
	"title": "Ensure Network Security is Enabled",
	"description": "",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_6.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

memorydb_clusters := fugue.resources("aws_memorydb_cluster")

network_security_enabled(cluster) {
	count(cluster.subnet_group_name) > 0
	count(cluster.security_group_ids) > 0
}

policy[p] {
	cluster := memorydb_clusters[_]
	network_security_enabled(cluster)
	p := fugue.allow_resource(cluster)
}

policy[p] {
	cluster := memorydb_clusters[_]
	not network_security_enabled(cluster)
	p := fugue.deny_resource_with_message(cluster, "Network security is not properly enabled for this Amazon MemoryDB cluster.")
}
