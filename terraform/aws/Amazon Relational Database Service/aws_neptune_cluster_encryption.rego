package rules.neptune_cluster_encryption

import data.fugue

__rego__metadoc__ := {
	"id": "Neptune.1",
	"title": "Neptune DB clusters should be encrypted at rest",
	"description": "This control checks if Neptune DB clusters are encrypted at rest. Encryption must be enabled during cluster creation and cannot be modified later.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Neptune.1"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

neptune_clusters = fugue.resources("aws_neptune_cluster")

# Helper function to check if cluster is encrypted
is_encrypted(cluster) {
	cluster.storage_encrypted == true
}

policy[p] {
	cluster := neptune_clusters[_]
	is_encrypted(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	not is_encrypted(cluster)
	p = fugue.deny_resource_with_message(cluster, "Neptune DB cluster must be encrypted at rest")
}
