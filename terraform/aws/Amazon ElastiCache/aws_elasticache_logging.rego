package rules.aws_elasticache_logging

import data.fugue

__rego__metadoc__ := {
	"id": "5.9",
	"title": "Ensure Audit Logging is Enabled",
	"description": "To manage your enterprise caching solution, it is important that you know how your clusters are performing and the resources they are consuming. It is also important that you know the events that are being generated and the costs of your deployment. Amazon CloudWatch provides metrics for monitoring your cache performance. In addition, cost allocation tags help you monitor and manage costs",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_5.9"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

clusters := fugue.resources("aws_elasticache_cluster")

# Check if log_delivery_configuration is defined for the cluster
audit_logging_enabled(cluster) {
	cluster.log_delivery_configuration[_].destination != ""
}

policy[p] {
	cluster := clusters[_]
	audit_logging_enabled(cluster)
	p := fugue.allow_resource(cluster)
}

policy[p] {
	cluster := clusters[_]
	not audit_logging_enabled(cluster)
	p := fugue.deny_resource(cluster)
}
