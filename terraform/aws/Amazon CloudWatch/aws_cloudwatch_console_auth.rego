package rules.aws_cloudwatch_console_auth

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "4.6",
	"title": "Ensure AWS Management Console authentication failures are monitored",
	"description": "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for failed console authentication attempts.",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_4.6"]}, "severity": "High", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

cloudwatch_log_groups := fugue.resources("aws_cloudwatch_log_group")

cloudwatch_metric_filters := fugue.resources("aws_cloudwatch_log_metric_filter")

cloudwatch_alarms := fugue.resources("aws_cloudwatch_metric_alarm")

required_pattern := "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"

has_required_metric_filter(log_group) {
	filter := cloudwatch_metric_filters[_]
	filter.log_group_name == log_group.name
	filter.pattern == required_pattern
}

has_alarm_for_metric_filter(metric_filter) {
	alarm := cloudwatch_alarms[_]
	alarm.metric_name == metric_filter.metric_transformation[_].name
}

policy[p] {
	log_group := cloudwatch_log_groups[_]
	not has_required_metric_filter(log_group)
	msg := sprintf("CloudWatch Log Group '%s' does not have the required metric filter for monitoring Management Console authentication failures", [log_group.name])
	p = fugue.deny_resource_with_message(log_group, msg)
}

policy[p] {
	metric_filter := cloudwatch_metric_filters[_]
	metric_filter.pattern == required_pattern
	not has_alarm_for_metric_filter(metric_filter)
	msg := sprintf("CloudWatch Metric Filter '%s' does not have an associated alarm for monitoring Management Console authentication failures", [metric_filter.name])
	p = fugue.deny_resource_with_message(metric_filter, msg)
}

policy[p] {
	log_group := cloudwatch_log_groups[_]
	has_required_metric_filter(log_group)
	metric_filter := cloudwatch_metric_filters[_]
	metric_filter.log_group_name == log_group.name
	metric_filter.pattern == required_pattern
	has_alarm_for_metric_filter(metric_filter)
	p = fugue.allow_resource(log_group)
}
