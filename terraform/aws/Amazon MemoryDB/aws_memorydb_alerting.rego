package rules.aws_memorydb_alerting

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "6.6",
	"title": "Ensure Monitoring and Alerting is Enabled",
	"description": "Implementing monitoring and alerting on Amazon MemoryDB allows you to proactively detect and respond to any performance issues, security events, or operational anomalies",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_6.6"]}},
}

resource_type := "MULTIPLE"

memorydb_clusters := fugue.resources("aws_memorydb_cluster")

cloudwatch_metric_alarms := fugue.resources("aws_cloudwatch_metric_alarm")

has_important_alarms(cluster) {
	important_metrics := {"CPUUtilization", "DatabaseMemoryUsagePercentage"}
	count([m | m := important_metrics[_]; has_alarm_for_metric(cluster, m)]) == count(important_metrics)
}

has_alarm_for_metric(cluster, metric) {
	some alarm in cloudwatch_metric_alarms
	alarm.metric_name == metric
	alarm.namespace == "AWS/MemoryDB"
	alarm.dimensions.ClusterName == cluster.name
}

policy[p] {
	cluster := memorydb_clusters[_]
	has_important_alarms(cluster)
	p := fugue.allow_resource(cluster)
}

policy[p] {
	cluster := memorydb_clusters[_]
	not has_important_alarms(cluster)
	msg := sprintf("MemoryDB cluster '%s' is missing important CloudWatch alarms", [cluster.name])
	p := fugue.deny_resource_with_message(cluster, msg)
}
