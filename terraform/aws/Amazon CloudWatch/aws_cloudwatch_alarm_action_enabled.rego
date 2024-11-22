package rules.aws_cloudwatch_alarm_action_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "CloudWatch.17",
	"title": "CloudWatch alarm actions should be activated",
	"description": "This control checks whether CloudWatch alarm actions are activated (ActionEnabled should be set to true). The control fails if the alarm action for a CloudWatch alarm is deactivated. This control focuses on the activation status of a CloudWatch alarm action, whereas CloudWatch.15 focuses on whether any ALARM action is configured in a CloudWatch alarm. Alarm actions automatically alert you when a monitored metric is outside the defined threshold. If the alarm action is deactivated, no actions are run when the alarm changes state, and you won't be alerted to changes in monitored metrics. We recommend activating CloudWatch alarm actions to help you quickly respond to security and operational issues.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudWatch.17"]},
		"severity": "High",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

alarms := fugue.resources("aws_cloudwatch_metric_alarm")

action_enabled(alarm) {
	alarm.actions_enabled
}

policy[p] {
	alarm := alarms[_]
	action_enabled(alarm)
	p := fugue.allow_resource(alarm)
}

policy[p] {
	alarm := alarms[_]
	not action_enabled(alarm)
	p := fugue.deny_resource_with_message(alarm, "CloudWatch alarm actions are not activated")
}
