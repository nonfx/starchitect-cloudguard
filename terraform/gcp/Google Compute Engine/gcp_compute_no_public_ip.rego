package rules.gcp_compute_no_public_ip

import data.fugue

__rego__metadoc__ := {
	"id": "4.9",
	"title": "Ensure That Compute Instances Do Not Have Public IP Addresses",
	"description": "Compute instances should not be configured to have external IP addresses to reduce attack surface.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.9"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all compute instance
google_compute_instance = fugue.resources("google_compute_instance")

# Helper to check if instance has public IP
has_public_ip(instance) {
	interface := instance.network_interface[_]
	interface.access_config != null
}

# Allow instances if shielded_instance_config exists and is properly configured
policy[p] {
	instance := google_compute_instance[_]
	not has_public_ip(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances if shielded_instance_config not exists and is not properly configured
policy[p] {
	instance := google_compute_instance[_]
	has_public_ip(instance)
	msg = sprintf("Instance %v has a public IP address configured. Remove access_config from network interfaces to prevent public access.", [instance.name])
	p = fugue.deny_resource_with_message(instance, msg)
}
