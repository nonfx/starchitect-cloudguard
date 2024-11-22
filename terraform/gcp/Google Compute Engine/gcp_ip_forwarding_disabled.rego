package rules.gcp_ip_forwarding_disabled

import data.fugue

__rego__metadoc__ := {
	"id": "4.6",
	"title": "Ensure That IP Forwarding Is Not Enabled on Instances",
	"description": "Compute Engine instance cannot forward a packet unless the source IP address of the packet matches the IP address of the instance. IP forwarding should be disabled to prevent unauthorized packet routing and data loss.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.6"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all compute instance
google_compute_instance = fugue.resources("google_compute_instance")

# Helper to check if serial ports are enabled
is_ip_forward_enable(resource) {
	resource.can_ip_forward == true
}

# Allow instances with ip forwarding disabed
policy[p] {
	instance := google_compute_instance[_]
	not is_ip_forward_enable(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances with ip forwarding enabled
policy[p] {
	instance := google_compute_instance[_]
	is_ip_forward_enable(instance)
	p = fugue.deny_resource_with_message(instance, "IP forwarding is enabled on the instance which may allow unauthorized packet routing")
}
