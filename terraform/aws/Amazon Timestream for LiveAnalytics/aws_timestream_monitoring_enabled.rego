package rules.aws_timestream_monitoring_enabled

import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "10.8",
	"title": "Ensure Monitoring and Alerting is Enabled - monitoring",
	"description": "Utilize Amazon CloudWatch to monitor key metrics, events, and logs related to Amazon Timestream. Set up appropriate alarms and notifications to detect security incidents or abnormal behavior proactively",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_10.8"]}},
}

resource_type := "MULTIPLE"

timestream_databases := fugue.resources("aws_timestreamwrite_database")

cloudwatch_log_groups := fugue.resources("aws_cloudwatch_log_group")

cloudwatch_metrics := fugue.resources("aws_cloudwatch_metric_alarm")

has_cloudwatch_log_group(database) {
	log_group := cloudwatch_log_groups[_]
	contains(log_group.name, database.id)
}

has_cloudwatch_metrics(database) {
	cpu_metric := cloudwatch_metrics[_]
	storage_metric := cloudwatch_metrics[_]
	latency_metric := cloudwatch_metrics[_]

	contains(cpu_metric.metric_name, "CPUUtilization")
	contains(cpu_metric.namespace, "AWS/Timestream")
	cpu_metric.threshold >= 80

	contains(storage_metric.metric_name, "StorageUsed")
	contains(storage_metric.namespace, "AWS/Timestream")
	storage_metric.threshold >= 80

	contains(latency_metric.metric_name, "SuccessfulRequestLatency")
	contains(latency_metric.namespace, "AWS/Timestream")
	latency_metric.threshold >= 1000
}

policy[p] {
	database := timestream_databases[_]
	has_cloudwatch_log_group(database)
	has_cloudwatch_metrics(database)
	p = fugue.allow_resource(database)
}

policy[p] {
	database := timestream_databases[_]
	not has_cloudwatch_log_group(database)
	msg := sprintf("Timestream database '%s' does not have monitoring enabled via CloudWatch log group.", [database.id])
	p = fugue.deny_resource_with_message(database, msg)
}

policy[p] {
	database := timestream_databases[_]
	not has_cloudwatch_metrics(database)
	msg := sprintf("Timestream database '%s' does not have key CloudWatch metrics (CPU utilization, storage usage, query latency) configured with appropriate thresholds.", [database.id])
	p = fugue.deny_resource_with_message(database, msg)
}
