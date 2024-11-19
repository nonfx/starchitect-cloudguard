package rules.aws_cloudwatch_log_group_retention

import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "CloudWatch.16",
	"title": "CloudWatch log groups should be retained for a specified time period",
	"description": "This control checks whether an Amazon CloudWatch log group has a retention period of at least the specified number of days. The control fails if the retention period is less than the specified number. Unless you provide a custom parameter value for the retention period, Security Hub uses a default value of 365 days. CloudWatch Logs centralize logs from all of your systems, applications, and AWS services in a single, highly scalable service. You can use CloudWatch Logs to monitor, store, and access your log files from Amazon Elastic Compute Cloud (EC2) instances, AWS CloudTrail, Amazon Route 53, and other sources. Retaining your logs for at least 1 year can help you comply with log retention standards.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudWatch.16"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

log_groups := fugue.resources("aws_cloudwatch_log_group")

min_retention_days := 365

has_sufficient_retention(group) {
	group.retention_in_days >= min_retention_days
}

policy[p] {
	group := log_groups[_]
	has_sufficient_retention(group)
	p := fugue.allow_resource(group)
}

policy[p] {
	group := log_groups[_]
	group.retention_in_days == 0 # Never expire
	p := fugue.allow_resource(group)
}

policy[p] {
	group := log_groups[_]
	group.retention_in_days < min_retention_days
	group.retention_in_days != 0
	msg := sprintf("CloudWatch log group '%s' has a retention period of %d days, which is less than the default 365 days. Please verify if this meets your custom retention requirements.", [group.name, group.retention_in_days])
	p := allow_resource_with_message(group, msg)
}

policy[p] {
	group := log_groups[_]
	not group.retention_in_days
	msg := sprintf("CloudWatch log group '%s' does not have a specified retention period. This means logs will be retained indefinitely. Please verify if this meets your retention requirements.", [group.name])
	p := fugue.deny_resource_with_message(group, msg)
}

allow_resource_with_message(resource, message) = ret {
	ret := fugue.allow({
		"resource": resource,
		"message": message,
	})
}
