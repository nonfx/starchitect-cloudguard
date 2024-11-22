package rules.gcp_https_lb_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "2.16",
	"title": "Ensure Logging is enabled for HTTP(S) Load Balancer",
	"description": "Logging enabled on a HTTPS Load Balancer will show all network traffic and its destination. This helps in monitoring and analyzing traffic patterns and potential security issues.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.16"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all backend services
backend_services = fugue.resources("google_compute_backend_service")

# Helper function to check if logging is properly configured
has_valid_logging(service) {
	service.log_config[_].enable == true
	service.log_config[_].sample_rate > 0
}

# Allow if backend service has logging properly configured
policy[p] {
	service := backend_services[_]
	has_valid_logging(service)
	p = fugue.allow_resource(service)
}

# Deny if backend service exists but logging is not properly configured
policy[p] {
	service := backend_services[_]
	not has_valid_logging(service)
	p = fugue.deny_resource_with_message(service, "HTTP(S) Load Balancer backend service must have logging enabled with a sample rate greater than 0")
}
