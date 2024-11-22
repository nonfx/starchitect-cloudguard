package rules.aws_timestream_monitoring_alerting

import data.fugue

__rego__metadoc__ := {
	"id": "10.8",
	"title": "Ensure Monitoring and Alerting is Enabled - alerting",
	"description": "Utilize Amazon CloudWatch to monitor key metrics, events, and logs related to Amazon Timestream. Set up appropriate alarms and notifications to detect security incidents or abnormal behavior proactively",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_10.8"]}, "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

timestream_databases = fugue.resources("aws_timestreamwrite_database")

cloudwatch_alarms = fugue.resources("aws_cloudwatch_metric_alarm")

# Check if CloudWatch alarms are set for Timestream
has_timestream_alarms(alarm) {
	alarm.namespace == "AWS/Timestream"
}

# Policy to ensure alarms are set if Timestream database exists
policy[p] {
	count(timestream_databases) > 0
	alarm := cloudwatch_alarms[_]
	has_timestream_alarms(alarm)
	p = fugue.allow_resource(alarm)
}

policy[p] {
	count(timestream_databases) > 0
	count(cloudwatch_alarms) == 0
	p = fugue.missing_resource_with_message("aws_cloudwatch_alarm", "No CloudWatch alarms found")
}

policy[p] {
	count(timestream_databases) > 0
	alarm := cloudwatch_alarms[_]
	not has_timestream_alarms(alarm)
	p = fugue.missing_resource_with_message("aws_cloudwatch_alarm", "No CloudWatch alarms found for Amazon Timestream")
}
