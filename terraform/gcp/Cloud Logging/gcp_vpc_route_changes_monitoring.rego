package rules.gcp_vpc_route_changes_monitoring

import data.fugue

__rego__metadoc__ := {
	"id": "2.8",
	"title": "Ensure That the Log Metric Filter and Alerts Exist for VPC Network Route Changes",
	"description": "Monitor VPC network route changes through log metric filters and alerts to ensure traffic flows through expected paths.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.8"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all log metric filters
log_metrics = fugue.resources("google_logging_metric")

# Check if metric filter has correct filter for VPC route changes
is_valid_metric_filter(metric) {
	contains(metric.filter, "resource.type=\"gce_route\"")
	contains(metric.filter, "methodName=\"compute.routes.delete\"")
	contains(metric.filter, "methodName=\"compute.routes.insert\"")
}

# Allow metric filters that are properly configured
policy[p] {
	metric := log_metrics[_]
	is_valid_metric_filter(metric)
	p = fugue.allow_resource(metric)
}

# Deny metric filters that are not properly configured
policy[p] {
	metric := log_metrics[_]
	not is_valid_metric_filter(metric)
	p = fugue.deny_resource_with_message(metric, "Log metric filter must monitor VPC route changes with correct filter criteria")
}

# Deny if no metric filter exists
policy[p] {
	count(log_metrics) == 0
	p = fugue.missing_resource_with_message("google_logging_metric", "Log metric filter for VPC route changes is required")
}
