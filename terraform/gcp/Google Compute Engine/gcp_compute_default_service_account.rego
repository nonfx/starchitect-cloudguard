package rules.gcp_compute_default_service_account

import data.fugue

__rego__metadoc__ := {
	"id": "4.1",
	"title": "Ensure That Instances Are Not Configured To Use the Default Service Account",
	"description": "Prevent default Compute Engine service account usage on instances to minimize security risks and privilege escalation.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all compute instances
instances = fugue.resources("google_compute_instance")

# Helper to check if instance uses default service account
is_default_service_account(instance) {
	sa := instance.service_account[_].email
	endswith(sa, "-compute@developer.gserviceaccount.com")
}

# Allow instances not using default service account
policy[p] {
	instance := instances[_]
	not is_default_service_account(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances using default service account
policy[p] {
	instance := instances[_]
	is_default_service_account(instance)
	p = fugue.deny_resource_with_message(instance, "Compute instance should not use the default compute service account")
}
