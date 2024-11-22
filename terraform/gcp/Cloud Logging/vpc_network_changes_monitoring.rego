package rules.vpc_network_changes_monitoring

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "2.9",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Changes",
	"description": "Monitor VPC network changes through log metric filters and alerts to ensure network traffic security and integrity.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.9"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all log metric filters and alert policies
log_metrics = fugue.resources("google_logging_metric")

alert_policies = fugue.resources("google_monitoring_alert_policy")

# Check if metric filter has correct filter configuration
is_valid_metric_filter(metric) {
	regex.match(`resource\.type\s*=\s*gce_network`, metric.filter)
	required_methods := {"insert", "patch", "delete", "removePeering", "addPeering"}
	all_methods_present := {method |
		method := required_methods[_]
		regex.match(sprintf(`protoPayload\.methodName\s*:\s*%s`, [method]), metric.filter)
	}

	# All methods should be present in the OR conditions
	count(all_methods_present) == count(required_methods)
}

# Check if alert policy is properly configured for the metric
is_valid_alert_policy(policy, metric) {
	condition := policy.conditions[_]
	contains(condition[_][_].filter, metric.name)
	condition[_][_].comparison == "COMPARISON_GT"
	condition[_][_].threshold_value >= 0
}

# Allow if both metric filter and alert policy exist and are properly configured
policy[p] {
	metric := log_metrics[_]
	is_valid_metric_filter(metric)
	alert_policy := alert_policies[_]
	is_valid_alert_policy(alert_policy, metric)
	p = fugue.allow_resource(metric)
}

# Deny if metric filter exists but is not properly configured
policy[p] {
	metric := log_metrics[_]
	not is_valid_metric_filter(metric)
	p = fugue.deny_resource_with_message(metric, "Log metric filter for VPC network changes is not properly configured")
}

# Deny if no alert policy exists for the metric
policy[p] {
	metric := log_metrics[_]
	alert_policy := alert_policies[_]
	not is_valid_alert_policy(alert_policy, metric)
	p = fugue.deny_resource_with_message(alert_policy, "NO Log metric filter for VPC network changes is not properly configured")
}
