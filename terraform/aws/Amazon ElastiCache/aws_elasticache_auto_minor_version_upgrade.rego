package rules.elasticache_auto_minor_version_upgrade

import data.fugue

__rego__metadoc__ := {
	"id": "ElastiCache.2",
	"title": "ElastiCache Redis clusters should have auto minor version upgrades enabled",
	"description": "ElastiCache Redis clusters must enable automatic minor version upgrades for enhanced security and bug fixes.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ElastiCache.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all ElastiCache clusters
elasticache_clusters = fugue.resources("aws_elasticache_cluster")

# Helper to check if auto minor version upgrade is enabled
is_auto_upgrade_enabled(cluster) {
	cluster.auto_minor_version_upgrade == true
}

# Allow clusters with auto minor version upgrade enabled
policy[p] {
	cluster := elasticache_clusters[_]
	is_auto_upgrade_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters without auto minor version upgrade enabled
policy[p] {
	cluster := elasticache_clusters[_]
	not is_auto_upgrade_enabled(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		"ElastiCache Redis cluster should have auto minor version upgrade enabled",
	)
}
