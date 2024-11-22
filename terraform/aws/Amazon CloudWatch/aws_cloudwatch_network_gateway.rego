package rules.aws_cloudwatch_network_gateway

import data.fugue

__rego__metadoc__ := {
	"id": "4.12",
	"title": "Ensure changes to network gateways are monitored",
	"description": "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. Network gateways are required to send/receive traffic to a destination outside of a VPC. It is recommended that a metric filter and alarm be established for changes to network gateways.",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_4.12"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudwatch_log_groups := fugue.resources("aws_cloudwatch_log_group")

cloudwatch_metric_filters := fugue.resources("aws_cloudwatch_log_metric_filter")

cloudwatch_alarms := fugue.resources("aws_cloudwatch_metric_alarm")

required_pattern := "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"

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
	msg := sprintf("CloudWatch Log Group '%s' does not have the required metric filter for monitoring route table changes.", [log_group.name])
	p = fugue.deny_resource_with_message(log_group, msg)
}

policy[p] {
	metric_filter := cloudwatch_metric_filters[_]
	metric_filter.pattern == required_pattern
	not has_alarm_for_metric_filter(metric_filter)
	msg := sprintf("CloudWatch Metric Filter '%s' does not have an associated alarm for monitoring route table changes.", [metric_filter.name])
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
