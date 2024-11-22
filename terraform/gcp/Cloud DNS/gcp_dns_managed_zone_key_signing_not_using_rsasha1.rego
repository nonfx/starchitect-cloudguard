package rules.dns_managed_zone_key_signing_not_using_rsasha1

import data.fugue

__rego__metadoc__ := {
	"id": "3.4",
	"title": "Ensure That RSASHA1 Is Not Used for the Key-Signing Key in Cloud DNS DNSSEC",
	"description": "This control checks that RSASHA1 is not used for DNS DNSSEC key-signing in Google Cloud DNS, as SHA1 has been removed from general use by Google and requires special whitelisting.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.4"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all DNS managed zones
dns_zones = fugue.resources("google_dns_managed_zone")

# Helper to check if DNSSEC is properly configured
is_valid_dnssec(zone) {
	some i, j
	zone.dnssec_config[i].default_key_specs[j].key_type == "keySigning"
	zone.dnssec_config[i].default_key_specs[j].algorithm != "rsasha1"
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
	p = fugue.deny_resource_with_message(zone, "DNS managed zone must not use RSASHA1 for key-signing keys in DNSSEC configuration")
}
