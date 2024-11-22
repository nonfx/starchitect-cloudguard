package rules.elasticache_no_default_subnet_group

import data.fugue

__rego__metadoc__ := {
	"id": "ElastiCache.7",
	"title": "ElastiCache clusters should not use the default subnet group",
	"description": "ElastiCache clusters must use custom subnet groups instead of default ones to ensure better network security and control.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ElastiCache.7"]}, "severity": "High"},
}

resource_type := "MULTIPLE"

# Get all ElastiCache clusters
cache_clusters = fugue.resources("aws_elasticache_cluster")

# Helper to check if subnet group is default
is_default_subnet_group(cluster) {
	cluster.subnet_group_name == "default"
}

# Allow clusters with custom subnet groups
policy[p] {
	cluster := cache_clusters[_]
	not is_default_subnet_group(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny clusters using default subnet group
policy[p] {
	cluster := cache_clusters[_]
	is_default_subnet_group(cluster)
	p = fugue.deny_resource_with_message(cluster, "ElastiCache cluster should not use the default subnet group")
}
