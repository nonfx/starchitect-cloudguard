package rules.gcp_project_ownership_monitoring

import data.fugue

__rego__metadoc__ := {
	"id": "2.4",
	"title": "Ensure Log Metric Filter and Alerts Exist for Project Ownership Changes",
	"description": "Monitor and alert on project ownership assignments/changes to prevent unauthorized access and maintain security compliance.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.4"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all log metric filters and alert policies
log_metrics = fugue.resources("google_logging_metric")

alert_policies = fugue.resources("google_monitoring_alert_policy")

is_valid_metric_filter(metric) {
	# Split into required components
	required_components := {
		# Resource type check
		`resource.type\s*=\s*"project"`,
		# Service name check
		`protoPayload.serviceName\s*=\s*"cloudresourcemanager.googleapis.com"`,
		# Method name check (case insensitive)
		`protoPayload.methodName\s*=\s*\(\s*"SetIamPolicy"\s*OR\s*"setIamPolicy"\s*\)`,
		# Action check
		`protoPayload.serviceData.policyDelta.bindingDeltas.action\s*=\s*\(\s*"ADD"\s*OR\s*"REMOVE"\s*\)`,
		# Role check
		`protoPayload.serviceData.policyDelta.bindingDeltas.role\s*=\s*"roles/owner"`,
	}

	# Check if all components are present in the filter
	filter := lower(metric.filter)

	# All components must be present
	all_components_present := {comp |
		comp := required_components[_]
		regex.match(lower(comp), filter)
	}

	# Verify all required components are found
	count(all_components_present) == count(required_components)
}

# Check if alert policy is properly configured
is_valid_alert_policy(policy) {
	condition := policy.conditions[_]
	condition.condition_threshold[_].filter == "resource.type = \"metric\" AND metric.type = \"logging.googleapis.com/user/project_ownership_changes\""
}

# Check if configuration is valid
is_valid_configuration {
	count(log_metrics) > 0
	count(alert_policies) > 0
	metric := log_metrics[_]
	alert := alert_policies[_]
	is_valid_metric_filter(metric)
	is_valid_alert_policy(alert)
}

# Allow if configuration is valid
policy[p] {
	is_valid_configuration
	metric := log_metrics[_]
	p = fugue.allow_resource(metric)
}

# Deny if configuration is invalid
policy[p] {
	not is_valid_configuration
	metric := log_metrics[_]
	p = fugue.deny_resource_with_message(metric, "Invalid configuration: Both log metric filter and alert policy must be properly configured for project ownership changes monitoring")
}

# Deny if resources are missing
policy[p] {
	count(log_metrics) == 0
	p = fugue.missing_resource_with_message("google_logging_metric", "Log metric filter for project ownership changes is required")
}

policy[p] {
	count(alert_policies) == 0
	p = fugue.missing_resource_with_message("google_monitoring_alert_policy", "Alert policy for project ownership changes is required")
}
