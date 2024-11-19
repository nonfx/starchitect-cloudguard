package rules.aws_neptune_monitoring

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "9.7.a",
	"title": "Ensure Monitoring is Enabled for AWS Neptune",
	"description": "Monitoring and alerting through AWS CloudWatch is essential for maintaining the health, availability, and performance of AWS Neptune databases.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_9.7"]}},
}

resource_type := "MULTIPLE"

neptune_clusters := fugue.resources("aws_neptune_cluster")

monitoring_enabled(cluster) {
	cluster.enable_cloudwatch_logs_exports != null
}

policy[p] {
	cluster := neptune_clusters[_]
	monitoring_enabled(cluster)
	p := fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	not monitoring_enabled(cluster)
	p := fugue.deny_resource_with_message(cluster, "AWS Neptune cluster does not have monitoring enabled.")
}
