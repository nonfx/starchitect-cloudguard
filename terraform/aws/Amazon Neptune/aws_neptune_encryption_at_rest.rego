package rules.aws_neptune_encryption_at_rest

import data.fugue

__rego__metadoc__ := {
	"id": "9.2",
	"title": "Ensure Data at Rest is Encrypted",
	"description": "This helps ensure that the data is kept secure and protected when at rest. The user must choose from two key options which then determine when the data is encrypted at rest.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_9.2"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

neptune_clusters = fugue.resources("aws_neptune_cluster")

cluster_encrypted(cluster) {
	cluster.storage_encrypted == true
}

policy[p] {
	cluster := neptune_clusters[_]
	cluster_encrypted(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	not cluster_encrypted(cluster)
	p = fugue.deny_resource_with_message(cluster, "Neptune cluster is not encrypted at rest")
}
