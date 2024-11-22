package rules.gcp_dns_dnssec_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "3.3",
	"title": "Ensure That DNSSEC Is Enabled for Cloud DNS",
	"description": "Cloud Domain Name System (DNS) zones should have DNSSEC enabled to protect against DNS hijacking and man-in-the-middle attacks.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.3"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all DNS managed zones
dns_zones = fugue.resources("google_dns_managed_zone")

# Helper to check if DNSSEC is enabled
is_dnssec_enabled(zone) {
	zone.dnssec_config[_].state == "on"
}

# Helper to check if zone is public
is_public_zone(zone) {
	zone.visibility == "public"
}

# Allow zones that have DNSSEC enabled
policy[p] {
	zone := dns_zones[_]
	is_public_zone(zone)
	is_dnssec_enabled(zone)
	p = fugue.allow_resource(zone)
}

# Deny public zones without DNSSEC enabled
policy[p] {
	zone := dns_zones[_]
	is_public_zone(zone)
	not is_dnssec_enabled(zone)
	p = fugue.deny_resource_with_message(zone, "DNSSEC must be enabled for public DNS zones")
}
