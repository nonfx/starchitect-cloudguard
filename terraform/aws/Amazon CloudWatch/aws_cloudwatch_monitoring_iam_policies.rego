package rules.aws_cloudwatch_iam_monitoring

import data.fugue

__rego__metadoc__ := {
	"id": "4.4",
	"title": "Ensure IAM policy changes are monitored",
	"description": "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established changes made to Identity and Access Management (IAM) policies.",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_4.4"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudwatch_log_groups := fugue.resources("aws_cloudwatch_log_group")

cloudwatch_metric_filters := fugue.resources("aws_cloudwatch_log_metric_filter")

cloudwatch_alarms := fugue.resources("aws_cloudwatch_metric_alarm")

required_pattern := "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}"

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
	msg := sprintf("CloudWatch Log Group '%s' does not have the required metric filter for monitoring IAM policy changes", [log_group.name])
	p = fugue.deny_resource_with_message(log_group, msg)
}

policy[p] {
	metric_filter := cloudwatch_metric_filters[_]
	metric_filter.pattern == required_pattern
	not has_alarm_for_metric_filter(metric_filter)
	msg := sprintf("CloudWatch Metric Filter '%s' does not have an associated alarm for monitoring IAM policy changes", [metric_filter.name])
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
