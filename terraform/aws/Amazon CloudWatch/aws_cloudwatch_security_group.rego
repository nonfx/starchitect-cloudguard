package rules.aws_cloudwatch_security_group

import data.fugue

__rego__metadoc__ := {
	"id": "4.10",
	"title": "Ensure security group changes are monitored",
	"description": "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs, or an external Security information and event management (SIEM) environment, and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingress and egress traffic within a VPC.",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_4.10"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all CloudTrails, CloudWatch Log Groups, and CloudWatch Metric Filters
cloud_trails = fugue.resources("aws_cloudtrail")

cloudwatch_log_groups = fugue.resources("aws_cloudwatch_log_group")

cloudwatch_metric_filters = fugue.resources("aws_cloudwatch_log_metric_filter")

# Check if CloudTrail is logging to CloudWatch Log Group
cloudtrail_logs_to_cloudwatch {
	cloudtrail = cloud_trails[_]
	cloudtrail.include_global_service_events
	cloudtrail.is_multi_region_trail
	cloudtrail.enable_log_file_validation
	cloudtrail.cloud_watch_logs_role_arn != ""
	cloudtrail.cloud_watch_logs_group_arn != ""
}

# Check if CloudWatch Log Group exists
cloudwatch_log_group_exists {
	log_group = cloudwatch_log_groups[_]
	log_group.name == "/aws/cloudtrail/cloudtrail-log-group"
}

# Check if CloudWatch Metric Filter for security group changes exists
cloudwatch_metric_filter_exists {
	metric_filter = cloudwatch_metric_filters[_]
	metric_filter.log_group_name == "/aws/cloudtrail/cloudtrail-log-group"
	metric_filter.pattern == "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
}

# Validate that all the necessary resources are in place
policy[r] {
	log_group := cloudwatch_log_groups[_]
	cloudtrail_logs_to_cloudwatch
	cloudwatch_log_group_exists
	cloudwatch_metric_filter_exists
	r = fugue.allow_resource(log_group)
}

policy[r] {
	not cloudtrail_logs_to_cloudwatch
	msg = "CloudTrail is not logging to CloudWatch Log Group."
	r = fugue.deny_resource_with_message("aws_cloudtrail", msg)
}

policy[r] {
	not cloudwatch_log_group_exists
	msg = "CloudWatch Log Group for CloudTrail logs does not exist."
	r = fugue.deny_resource_with_message("aws_cloudwatch_log_group", msg)
}

policy[r] {
	not cloudwatch_metric_filter_exists
	msg = "CloudWatch Metric Filter for security group changes does not exist."
	r = fugue.deny_resource_with_message("aws_cloudwatch_log_metric_filter", msg)
}
