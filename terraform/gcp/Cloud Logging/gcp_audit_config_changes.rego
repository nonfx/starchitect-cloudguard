package rules.gcp_audit_config_changes

import data.fugue

__rego__metadoc__ := {
	"id": "2.5",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for Audit Configuration Changes",
	"description": "Monitor and alert on GCP audit configuration changes using log metrics and alert policies for security compliance.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.5"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

metrics = fugue.resources("google_logging_metric")

alert_policies = fugue.resources("google_monitoring_alert_policy")

is_valid_metric(metric) {
	metric.filter == "protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*"
	metric.metric_descriptor[_].metric_kind == "DELTA"
}

is_valid_alert(policy) {
	policy.conditions[_].condition_threshold[_].comparison == "COMPARISON_GT"
	policy.conditions[_].condition_threshold[_].threshold_value == 0
	policy.conditions[_].condition_threshold[_].duration == "0s"
}

policy[p] {
	metric := metrics[_]
	is_valid_metric(metric)
	alert_policy := alert_policies[_]
	is_valid_alert(alert_policy)
	p = fugue.allow_resource(metric)
}

policy[p] {
	metric := metrics[_]
	not is_valid_metric(metric)
	p = fugue.deny_resource_with_message(metric, "Invalid metric configuration for audit changes monitoring")
}

policy[p] {
	alert_policy := alert_policies[_]
	not is_valid_alert(alert_policy)
	p = fugue.deny_resource_with_message(alert_policy, "Alert policy not properly configured for audit changes")
}
