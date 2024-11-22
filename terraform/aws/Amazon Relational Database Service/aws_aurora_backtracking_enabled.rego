package rules.aurora_backtracking_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.14",
	"title": "Amazon Aurora clusters should have backtracking enabled",
	"description": "This control checks whether Amazon Aurora clusters have backtracking enabled for point-in-time recovery capabilities.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.14"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Aurora DB clusters
clusters = fugue.resources("aws_rds_cluster")

# Helper to check if cluster has backtracking enabled
has_backtracking(cluster) {
	cluster.backtrack_window > 0
}

# Helper to check if cluster is Aurora
is_aurora(cluster) {
	startswith(cluster.engine, "aurora")
}

# Allow if cluster has backtracking enabled
policy[p] {
	cluster := clusters[_]
	is_aurora(cluster)
	has_backtracking(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny if cluster doesn't have backtracking enabled
policy[p] {
	cluster := clusters[_]
	is_aurora(cluster)
	not has_backtracking(cluster)
	p = fugue.deny_resource_with_message(cluster, "Aurora cluster must have backtracking enabled for point-in-time recovery")
}
