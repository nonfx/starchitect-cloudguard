package rules.gcp_sql_instance_config_changes

import data.fugue

__rego__metadoc__ := {
	"id": "2.11",
	"title": "Ensure Log Metric Filter and Alerts Exist for SQL Instance Configuration Changes",
	"description": "Monitor SQL instance configuration changes through metric filters and alerts to detect and respond to security-impacting modifications.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.11"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all log metric filters and alert policies
log_metrics = fugue.resources("google_logging_metric")

alert_policies = fugue.resources("google_monitoring_alert_policy")

# Helper to check if metric filter has correct configuration
is_valid_metric_filter(metric) {
	metric.filter == "resource.type=\"cloudsql_database\" AND protoPayload.methodName=\"cloudsql.instances.update\""
}

# Helper to check if alert policy is properly configured
is_valid_alert_policy(policy, metric_name) {
	condition := policy.conditions[_]
	condition.display_name == "SQL Instance Configuration Changes"
	expected_filter := concat("", ["metric.type=\"", metric_name, "\""])
	condition.condition_threshold[_].filter == expected_filter
}

# Rule to evaluate resources
policy[p] {
	# Get the metric and validate it
	metric := log_metrics[_]
	is_valid_metric_filter(metric)

	# Check for valid alert policy
	alert := alert_policies[_]
	is_valid_alert_policy(alert, metric.name)

	# Allow if both conditions are met
	p = fugue.allow_resource(metric)
}

policy[p] {
	# Deny invalid metrics
	metric := log_metrics[_]
	not is_valid_metric_filter(metric)
	p = fugue.deny_resource_with_message(
		metric,
		"Log metric filter for SQL instance configuration changes is not properly configured",
	)
}

policy[p] {
	# Deny metrics without valid alert policies
	metric := log_metrics[_]
	alert := alert_policies[_]
	not is_valid_alert_policy(alert, metric.name)
	p = fugue.deny_resource_with_message(
		metric,
		"No properly configured alert policy found for the metric",
	)
}
