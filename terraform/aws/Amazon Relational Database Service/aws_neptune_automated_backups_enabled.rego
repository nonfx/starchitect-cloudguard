package rules.neptune_automated_backups_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "Neptune.5",
	"title": "Neptune DB clusters should have automated backups enabled",
	"description": "This control checks if Neptune DB clusters have automated backups enabled with a retention period of at least 7 days.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Neptune.5"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

neptune_clusters = fugue.resources("aws_neptune_cluster")

# Minimum required backup retention period in days
min_retention_period = 7

# Helper function to check if backups are properly configured
has_valid_backups(cluster) {
	cluster.backup_retention_period >= min_retention_period
}

policy[p] {
	cluster := neptune_clusters[_]
	has_valid_backups(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	not has_valid_backups(cluster)
	p = fugue.deny_resource_with_message(cluster, sprintf("Neptune DB cluster must have automated backups enabled with retention period of at least %d days", [min_retention_period]))
}
