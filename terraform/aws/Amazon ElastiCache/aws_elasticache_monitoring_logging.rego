package rules.aws_elasticache_monitoring_logging

import data.fugue

__rego__metadoc__ := {
	"id": "5.6",
	"title": "Ensure Monitoring and Logging is Enabled for ElastiCache",
	"description": "Implementing monitoring and logging for Amazon ElastiCache allows you to gain visibility into the performance, health, and behavior of your ElastiCache clusters.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_5.6"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Query for all RDS instances
aws_elasticache_clusters = fugue.resources("aws_elasticache_cluster")

cloudwatch_logs_enabled(resource) {
	resource.log_delivery_configuration[_].destination_type == "cloudwatch-logs"
	resource.log_delivery_configuration[_].destination != ""
	resource.log_delivery_configuration[_].log_format != ""
	resource.log_delivery_configuration[_].log_type != ""
}

policy[p] {
	resource := aws_elasticache_clusters[_]
	cloudwatch_logs_enabled(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := aws_elasticache_clusters[_]
	not cloudwatch_logs_enabled(resource)
	msg := sprintf("ElastiCache cluster '%s' does not have CloudWatch logs enabled", [resource.id])
	p = fugue.deny_resource_with_message(resource, msg)
}
