package rules.route53_query_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "Route53.2",
	"title": "Route 53 public hosted zones should log DNS queries",
	"description": "Route 53 public hosted zones must enable DNS query logging for security monitoring and compliance requirements. DNS query logs provide visibility into DNS queries and help detect malicious activities.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Route53.2"]}, "severity": "Medium", "author": "llmagent"},
}

resource_type := "MULTIPLE"

# Get all Route53 hosted zones and query logging configs
hosted_zones = fugue.resources("aws_route53_zone")

query_logs = fugue.resources("aws_route53_query_log")

# Helper to check if zone has query logging enabled
has_query_logging(zone) {
	log := query_logs[_]
	log.zone_id == zone.zone_id
}

# Allow if zone has query logging enabled
policy[p] {
	zone := hosted_zones[_]
	has_query_logging(zone)
	p = fugue.allow_resource(zone)
}

# Deny if zone does not have query logging
policy[p] {
	zone := hosted_zones[_]
	not has_query_logging(zone)
	p = fugue.deny_resource_with_message(zone, "Route 53 public hosted zone must have DNS query logging enabled")
}
