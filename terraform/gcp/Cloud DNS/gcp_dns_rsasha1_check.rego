package rules.gcp_dns_rsasha1_check

import data.fugue

__rego__metadoc__ := {
	"id": "3.5",
	"title": "Ensure That RSASHA1 Is Not Used for the Zone-Signing Key in Cloud DNS DNSSEC",
	"description": "This rule ensures that RSASHA1 is not used for DNS zone-signing keys in Google Cloud DNS DNSSEC for enhanced security.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.5"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all DNS managed zones
dns_zones = fugue.resources("google_dns_managed_zone")

# Helper to check if DNSSEC is properly configured
is_valid_dnssec(zone) {
	zone.dnssec_config[_].default_key_specs[_].key_type == "zoneSigning"
	zone.dnssec_config[_].default_key_specs[_].algorithm != "rsasha1"
}

# Allow zones with proper DNSSEC configuration
policy[p] {
	zone := dns_zones[_]
	is_valid_dnssec(zone)
	p = fugue.allow_resource(zone)
}

# Deny zones using RSASHA1
policy[p] {
	zone := dns_zones[_]
	not is_valid_dnssec(zone)
	p = fugue.deny_resource_with_message(zone, "DNS managed zone must not use RSASHA1 for zone-signing keys in DNSSEC configuration")
}
