package rules.aws_neptune_alerting_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "9.7.b",
	"title": "Ensure Monitoring and Alerting is Enabled - Alerting",
	"description": "",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_9.7"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

neptune_clusters := fugue.resources("aws_neptune_cluster")

cloudwatch_alarms := fugue.resources("aws_cloudwatch_metric_alarm")

has_neptune_alarm(cluster, alarms) {
	alarm := alarms[_]
	contains(alarm.alarm_name, cluster.cluster_identifier)
}

policy[p] {
	cluster := neptune_clusters[_]
	has_neptune_alarm(cluster, cloudwatch_alarms)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	not has_neptune_alarm(cluster, cloudwatch_alarms)
	msg := sprintf("Neptune cluster '%s' does not have any associated CloudWatch alarms for alerting.", [cluster.cluster_identifier])
	p = fugue.deny_resource_with_message(cluster, msg)
}
