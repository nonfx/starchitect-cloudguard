package rules.aws_cloudwatch_vpc_changes_monitored

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "4.14",
	"title": "Ensure VPC changes are monitored",
	"description": "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. It is possible to have more than 1 VPC within an account, in addition it is also possible to create a peer connection between 2 VPCs enabling network traffic to route between VPCs. It is recommended that a metric filter and alarm be established for changes made to VPCs.",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_4.14"]}},
}

resource_type := "MULTIPLE"

cloudwatch_log_groups := fugue.resources("aws_cloudwatch_log_group")

cloudwatch_metric_filters := fugue.resources("aws_cloudwatch_log_metric_filter")

cloudwatch_alarms := fugue.resources("aws_cloudwatch_metric_alarm")

required_pattern := "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"

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
	msg := sprintf("CloudWatch Log Group '%s' does not have the required metric filter for monitoring VPC changes.", [log_group.name])
	p = fugue.deny_resource_with_message(log_group, msg)
}

policy[p] {
	metric_filter := cloudwatch_metric_filters[_]
	metric_filter.pattern == required_pattern
	not has_alarm_for_metric_filter(metric_filter)
	msg := sprintf("CloudWatch Metric Filter '%s' does not have an associated alarm for monitoring VPC changes.", [metric_filter.name])
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
