package rules.gcp_rdp_restricted

import data.fugue

__rego__metadoc__ := {
	"id": "3.7",
	"title": "Ensure That RDP Access Is Restricted From the Internet",
	"description": "GCP Firewall Rules should restrict RDP access from the internet (0.0.0.0/0) to maintain security of VPC networks and instances.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.7"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

firewall_rules = fugue.resources("google_compute_firewall")

# Helper function to check if rule allows unrestricted RDP access
has_unrestricted_rdp(rule) {
	rule.direction == "INGRESS"
	allow := rule.allow[_]
	allow.protocol == "tcp"
	allow.ports[_] == "3389"
	rule.source_ranges[_] == "0.0.0.0/0"
}

# Allow if firewall rule doesn't allow unrestricted RDP access
policy[p] {
	rule := firewall_rules[_]
	not has_unrestricted_rdp(rule)
	p = fugue.allow_resource(rule)
}

# Deny if firewall rule allows unrestricted RDP access
policy[p] {
	rule := firewall_rules[_]
	has_unrestricted_rdp(rule)
	p = fugue.deny_resource_with_message(
		rule,
		"Firewall rule allows unrestricted RDP access (port 3389) from the internet (0.0.0.0/0). Restrict source IP ranges for RDP access.",
	)
}
