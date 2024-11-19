package rules.ecs_container_insights_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "ECS.12",
	"title": "ECS clusters should use Container Insights",
	"description": "ECS clusters must enable Container Insights for monitoring metrics, logs, and diagnostics to maintain reliability and performance.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ECS.12"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all ECS clusters
ecs_clusters = fugue.resources("aws_ecs_cluster")

# Helper function to check if Container Insights is enabled
has_container_insights(cluster) {
	cluster.setting[_].name == "containerInsights"
	cluster.setting[_].value == "enabled"
}

# Allow if Container Insights is enabled
policy[p] {
	cluster := ecs_clusters[_]
	has_container_insights(cluster)
	p = fugue.allow_resource(cluster)
}

# Deny if Container Insights is not enabled
policy[p] {
	cluster := ecs_clusters[_]
	not has_container_insights(cluster)
	p = fugue.deny_resource_with_message(cluster, "ECS cluster does not have Container Insights enabled")
}
