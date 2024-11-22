package rules.gcp_compute_default_service_account

import data.fugue

__rego__metadoc__ := {
	"id": "4.2",
	"title": "Ensure instances are not configured to use the default service account with full access to all Cloud APIs",
	"description": "VM instances should not use the default service account with full API access to maintain least privilege principle and prevent potential privilege escalation.",
	"custom": {
		"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.2"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

# Get all compute instances
instances = fugue.resources("google_compute_instance")

# Helper to check if instance uses default service account
uses_default_service_account(instance) {
	sa := instance.service_account[_]
	sa.email == "default"
}

# Helper to check if service account has full access
has_full_access(instance) {
	sa := instance.service_account[_]
	scope := sa.scopes[_]
	scope == "https://www.googleapis.com/auth/cloud-platform"
}

# Allow instances that don't use default service account or don't have full access
policy[p] {
	instance := instances[_]
	not uses_default_service_account(instance)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := instances[_]
	not has_full_access(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances using default service account with full access
policy[p] {
	instance := instances[_]
	uses_default_service_account(instance)
	has_full_access(instance)
	p = fugue.deny_resource_with_message(instance, "VM instance should not use default service account with full Cloud API access")
}
