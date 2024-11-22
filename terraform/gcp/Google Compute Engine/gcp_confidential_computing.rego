package rules.gcp_confidential_computing

import data.fugue

__rego__metadoc__ := {
	"id": "4.11",
	"title": "Ensure That Compute Instances Have Confidential Computing Enabled",
	"description": "Compute instances must have Confidential Computing enabled to encrypt data during processing using AMD EPYC CPUs' SEV feature.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.11"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all compute instance
google_compute_instance = fugue.resources("google_compute_instance")

# Helper to check if Confidential Computing is enabled
is_confidential_computing_enabled(instance) {
	instance.confidential_instance_config[_].enable_confidential_compute == true
}

# Allow instances if Confidential Computing is enabled
policy[p] {
	instance := google_compute_instance[_]
	is_confidential_computing_enabled(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances if Confidential Computing is disabled
policy[p] {
	instance := google_compute_instance[_]
	not is_confidential_computing_enabled(instance)
	msg = sprintf("Instance %v does not have Confidential Computing enabled. Enable confidential_instance_config for enhanced data security.", [instance.name])
	p = fugue.deny_resource_with_message(instance, msg)
}
