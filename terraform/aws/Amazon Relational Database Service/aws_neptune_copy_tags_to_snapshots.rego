package rules.neptune_copy_tags_to_snapshots

import data.fugue

__rego__metadoc__ := {
	"id": "Neptune.8",
	"title": "Neptune DB clusters should be configured to copy tags to snapshots",
	"description": "Neptune DB clusters must be configured to automatically copy all tags to snapshots for consistent metadata and access policies.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Neptune.8"]}, "severity": "Low"},
}

resource_type := "MULTIPLE"

neptune_clusters = fugue.resources("aws_neptune_cluster")

# Helper function to check if copy_tags_to_snapshot is enabled
is_copy_tags_enabled(cluster) {
	cluster.copy_tags_to_snapshot == true
}

policy[p] {
	cluster := neptune_clusters[_]
	is_copy_tags_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	not is_copy_tags_enabled(cluster)
	p = fugue.deny_resource_with_message(cluster, "Neptune DB cluster should have copy_tags_to_snapshot enabled")
}
