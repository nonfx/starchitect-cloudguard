package rules.gcp_shielded_vm_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "4.8",
	"title": "Ensure Compute Instances Are Launched With Shielded VM Enabled",
	"description": "To defend against advanced threats and ensure that the boot loader and firmware on your VMs are signed and untampered, Compute instances must have Shielded VM enabled.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.8"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all compute instance
google_compute_instance = fugue.resources("google_compute_instance")

# Helper to check if Shielded VM is properly configured
is_shielded_vm_enabled(resource) {
	resource.shielded_instance_config[_].enable_vtpm == true
	resource.shielded_instance_config[_].enable_integrity_monitoring == true
}

# Allow instances if shielded_instance_config exists and is properly configured
policy[p] {
	instance := google_compute_instance[_]
	is_shielded_vm_enabled(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances if shielded_instance_config not exists and is not properly configured
policy[p] {
	instance := google_compute_instance[_]
	not is_shielded_vm_enabled(instance)
	p = fugue.deny_resource_with_message(instance, "IP forwarding is enabled on the instance which may allow unauthorized packet routing")
}
