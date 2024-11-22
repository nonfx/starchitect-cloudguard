package rules.aws_memorydb_encryption_at_rest

import data.fugue

__rego__metadoc__ := {
	"id": "6.2.a",
	"title": "Ensure Data at Rest and in Transit is Encrypted - at rest",
	"description": "",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_6.2"]}, "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

memorydb_clusters = fugue.resources("aws_memorydb_cluster")

cluster_encrypted_at_rest(cluster) {
	cluster.kms_key_arn != null
}

policy[p] {
	cluster := memorydb_clusters[_]
	cluster_encrypted_at_rest(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := memorydb_clusters[_]
	not cluster_encrypted_at_rest(cluster)
	p = fugue.deny_resource_with_message(cluster, "MemoryDB cluster is not encrypted at rest.")
}
