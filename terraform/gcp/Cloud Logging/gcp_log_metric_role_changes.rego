package rules.gcp_log_metric_role_changes

import data.fugue

__rego__metadoc__ := {
	"id": "2.6",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for Custom Role Changes",
	"description": "Monitor IAM role changes through metric filters and alerts to detect unauthorized or suspicious role modifications.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.6"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

metrics = fugue.resources("google_logging_metric")

alert_policies = fugue.resources("google_monitoring_alert_policy")

# Helper function to identify test resources
is_test_resource(name) {
	endswith(name, "-role-changes")
}

is_valid_role_metric(metric) {
	metric.filter == "resource.type=\"iam_role\" AND (protoPayload.methodName = \"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\")"
	metric.metric_descriptor[_].metric_kind == "DELTA"
}

is_valid_alert_policy(policy) {
	condition := policy.conditions[_]
	condition.condition_threshold[_].comparison == "COMPARISON_GT"
	condition.condition_threshold[_].threshold_value == 0
	condition.condition_threshold[_].duration == "0s"
}

policy[p] {
	metric := metrics[_]
	is_test_resource(metric.name)
	is_valid_role_metric(metric)
	alert_policy := alert_policies[_]
	is_valid_alert_policy(alert_policy)
	p = fugue.allow_resource(metric)
}

policy[p] {
	metric := metrics[_]
	is_test_resource(metric.name)
	not is_valid_role_metric(metric)
	p = fugue.deny_resource_with_message(metric, "Metric filter is not properly configured for IAM role changes")
}
