package rules.elb_acm_certificate_required

import data.fugue

__rego__metadoc__ := {
	"id": "ELB.2",
	"title": "Classic Load Balancers with SSL/HTTPS listeners should use ACM certificates",
	"description": "Classic Load Balancers must use AWS Certificate Manager certificates for SSL/HTTPS listeners to ensure secure data transmission.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ELB.2"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Classic Load Balancers
elbs = fugue.resources("aws_elb")

values = ["HTTPS", "SSL"]

# Helper to check if listener uses ACM certificate
uses_acm_certificate(listener) {
	contains(listener.ssl_certificate_id, ":acm:")
}

# Helper to check if listener is SSL/HTTPS
is_ssl_listener(listener) {
	listener.lb_protocol = values[_]
}

# Helper to validate all SSL/HTTPS listeners use ACM certificates
has_valid_certificates(elb) {
	listener := elb.listener[_]
	is_ssl_listener(listener)
	uses_acm_certificate(listener)
}

# Allow if all SSL/HTTPS listeners use ACM certificates
policy[p] {
	elb := elbs[_]
	has_valid_certificates(elb)
	p = fugue.allow_resource(elb)
}

# Deny if any SSL/HTTPS listener doesn't use ACM certificate
policy[p] {
	elb := elbs[_]
	not has_valid_certificates(elb)
	p = fugue.deny_resource_with_message(elb, "Classic Load Balancer must use AWS Certificate Manager certificates for all SSL/HTTPS listeners")
}
