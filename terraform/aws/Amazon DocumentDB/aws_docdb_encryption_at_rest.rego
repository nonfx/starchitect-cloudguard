package rules.aws_docdb_encryption_at_rest

import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "7.3",
	"title": "Ensure Encryption at Rest is Enabled",
	"description": "This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_7.3"]}},
}

resource_type := "MULTIPLE"

docdb_clusters = fugue.resources("aws_docdb_cluster")

cluster_encrypted(cluster) {
	cluster.storage_encrypted == true
}

policy[p] {
	cluster := docdb_clusters[_]
	cluster_encrypted(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := docdb_clusters[_]
	not cluster_encrypted(cluster)
	p = fugue.deny_resource_with_message(cluster, "DocumentDB cluster is not encrypted at rest")
}
