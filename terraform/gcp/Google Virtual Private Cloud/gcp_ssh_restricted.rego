package rules.gcp_ssh_restricted

import data.fugue

__rego__metadoc__ := {
	"id": "3.6",
	"title": "Ensure That SSH Access Is Restricted From the Internet",
	"description": "GCP Firewall Rules should restrict SSH access from the internet (0.0.0.0/0) to maintain security of VPC networks and instances.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.6"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

google_compute_firewall := fugue.resources("google_compute_firewall")

# Check if rule allows SSH access from anywhere
allows_unrestricted_ssh(rule) {
	rule.direction == "INGRESS"
	allow := rule.allow[_]
	allow.protocol == "tcp"
	allow.ports[_] == "22"
	rule.source_ranges[_] == "0.0.0.0/0"
}

# Deny if rule allows unrestricted SSH access
policy[p] {
	resource := google_compute_firewall[_]
	allows_unrestricted_ssh(resource)
	p = fugue.deny_resource_with_message(
		resource,
		"Firewall rule allows unrestricted SSH access (port 22) from the internet (0.0.0.0/0)",
	)
}

# Allow if rule doesn't allow unrestricted SSH access
policy[p] {
	resource := google_compute_firewall[_]
	not allows_unrestricted_ssh(resource)
	p = fugue.allow_resource(resource)
}
