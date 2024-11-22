package rules.aws_cloudwatch_alarm_action_check

import data.fugue

__rego__metadoc__ := {
	"id": "CloudWatch.15",
	"title": "CloudWatch alarms should have specified actions configured",
	"description": "This control checks whether an Amazon CloudWatch alarm has at least one action configured for the ALARM state. The control fails if the alarm doesn't have an action configured for the ALARM state. Optionally, you can include custom parameter values to also require alarm actions for the INSUFFICIENT_DATA or OK states. This control focuses on whether a CloudWatch alarm has an alarm action configured, whereas CloudWatch.17 focuses on the activation status of a CloudWatch alarm action. We recommend CloudWatch alarm actions to automatically alert you when a monitored metric is outside the defined threshold. Monitoring alarms help you identify unusual activities and quickly respond to security and operational issues when an alarm goes into a specific state. The most common type of alarm action is to notify one or more users by sending a message to an Amazon Simple Notification Service (Amazon SNS) topi",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.15"]},
		"severity": "High",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

alarms = fugue.resources("aws_cloudwatch_metric_alarm")

has_alarm_action(alarm) {
	count(alarm.alarm_actions) > 0
}

has_insufficient_data_action(alarm) {
	count(alarm.insufficient_data_actions) > 0
}

has_ok_action(alarm) {
	count(alarm.ok_actions) > 0
}

policy[p] {
	alarm := alarms[_]
	has_alarm_action(alarm)
	p = fugue.allow_resource(alarm)
}

policy[p] {
	alarm := alarms[_]
	not has_alarm_action(alarm)
	msg := sprintf("CloudWatch alarm '%s' does not have an action configured for the ALARM state", [alarm.alarm_name])
	p = fugue.deny_resource_with_message(alarm, msg)
}

# Optional checks for INSUFFICIENT_DATA and OK states
policy[p] {
	alarm := alarms[_]
	not has_insufficient_data_action(alarm)
	msg := sprintf("CloudWatch alarm '%s' does not have an action configured for the INSUFFICIENT_DATA state", [alarm.alarm_name])
	p = allow_resource_with_message(alarm, msg)
}

policy[p] {
	alarm := alarms[_]
	not has_ok_action(alarm)
	msg := sprintf("CloudWatch alarm '%s' does not have an action configured for the OK state", [alarm.alarm_name])
	p = allow_resource_with_message(alarm, msg)
}

allow_resource_with_message(resource, message) = ret {
	ret := fugue.allow({
		"resource": resource,
		"message": message,
	})
}
