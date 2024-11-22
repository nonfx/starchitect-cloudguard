package rules.gcp_vm_serial_ports_disabled

import data.fugue

__rego__metadoc__ := {
	"id": "4.5",
	"title": "Ensure 'Enable Connecting to Serial Ports' Is Not Enabled for VM Instance",
	"description": "VM instances should not have serial port access enabled as it allows connections from any IP address without IP-based restrictions.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.5"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all compute instances
instances = fugue.resources("google_compute_instance")

# Helper to check if serial ports are enabled
is_serial_ports_enabled(resource) {
	resource.metadata["serial-port-enable"] == "TRUE"
}

# Allow instances with serial ports disabled
policy[allow_resource] {
	instance := instances[_]
	not is_serial_ports_enabled(instance)
	allow_resource = fugue.allow_resource(instance)
}

# Deny instances with serial ports enabled
policy[deny_resource] {
	instance := instances[_]
	is_serial_ports_enabled(instance)
	deny_resource = fugue.deny_resource_with_message(
		instance,
		sprintf("VM instance '%v' has serial port access enabled, which poses a security risk", [instance.name]),
	)
}
