package rules.neptune_deletion_protection_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "Neptune.4",
	"title": "Neptune DB clusters should have deletion protection enabled",
	"description": "This control checks if Neptune DB clusters have deletion protection enabled to prevent accidental or unauthorized database deletion.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Neptune.4"]}, "severity": "Low", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

neptune_clusters = fugue.resources("aws_neptune_cluster")

# Helper function to check if deletion protection is enabled
is_deletion_protected(cluster) {
	cluster.deletion_protection == true
}

policy[p] {
	cluster := neptune_clusters[_]
	is_deletion_protected(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	not is_deletion_protected(cluster)
	p = fugue.deny_resource_with_message(cluster, "Neptune DB cluster must have deletion protection enabled")
}
