package rules.gcp_vpc_firewall_rule_changes

import data.fugue

__rego__metadoc__ := {
	"id": "2.7",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Firewall Rule Changes",
	"description": "Monitor and alert on VPC Network Firewall rule changes through log metric filters for enhanced security visibility.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.7"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all log metric filters and alert policies
log_metrics = fugue.resources("google_logging_metric")

alerting_policies = fugue.resources("google_monitoring_alert_policy")

# Helper function to check if metric filter contains required criteria
has_valid_filter(metric) {
	filter := lower(metric.filter)
	contains(filter, "resource.type=\"gce_firewall_rule\"")
	regex.match(`.*methodname="compute\.firewalls\.(patch|insert|delete)".*`, filter)
}

# Helper function to check if alert policy is properly configured
has_valid_alert(policy) {
	condition := policy.conditions[_]
	condition.condition_threshold[_].comparison == "COMPARISON_GT"
	condition.condition_threshold[_].threshold_value == 0
	condition.condition_threshold[_].duration == "0s"
}

# Helper function to check if configuration is valid
is_valid_config {
	count(log_metrics) > 0
	count(alerting_policies) > 0
	metric := log_metrics[_]
	alert := alerting_policies[_]
	has_valid_filter(metric)
	has_valid_alert(alert)
}

# Allow if configuration is valid
policy[p] {
	is_valid_config
	resource := log_metrics[_]
	has_valid_filter(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	is_valid_config
	resource := alerting_policies[_]
	has_valid_alert(resource)
	p = fugue.allow_resource(resource)
}

# Deny if configuration is invalid
policy[p] {
	not is_valid_config
	resource := log_metrics[_]
	p = fugue.deny_resource_with_message(resource, "Log metric filter must include all required criteria for monitoring VPC firewall rule changes")
}

policy[p] {
	not is_valid_config
	resource := alerting_policies[_]
	p = fugue.deny_resource_with_message(resource, "Alert policy must be configured with threshold value of 0 and proper comparison operator")
}
