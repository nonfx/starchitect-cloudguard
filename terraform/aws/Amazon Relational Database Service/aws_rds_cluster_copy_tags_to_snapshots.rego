package rules.rds_cluster_copy_tags_to_snapshots

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.16",
	"title": "RDS DB clusters should be configured to copy tags to snapshots",
	"description": "RDS DB clusters must be configured to automatically copy all resource tags to snapshots when created.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.16"]}, "severity": "Low", "author": "llmagent"},
}

resource_type := "MULTIPLE"

db_clusters = fugue.resources("aws_rds_cluster")

# Helper function to check if copy_tags_to_snapshot is enabled
is_copy_tags_enabled(cluster) {
	cluster.copy_tags_to_snapshot == true
}

# Allow clusters with copy_tags_to_snapshot enabled
policy[p] {
	cluster := db_clusters[_]
	is_copy_tags_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters without copy_tags_to_snapshot enabled
policy[p] {
	cluster := db_clusters[_]
	not is_copy_tags_enabled(cluster)
	p = fugue.deny_resource_with_message(cluster, "RDS DB cluster must be configured to copy tags to snapshots")
}
