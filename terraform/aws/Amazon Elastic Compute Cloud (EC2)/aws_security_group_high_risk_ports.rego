package rules.security_group_high_risk_ports

import data.fugue

__rego__metadoc__ := {
	"id": "EC2.19",
	"title": "Security groups should not allow unrestricted access to ports with high risk",
	"description": "This control checks if security groups restrict access to high-risk ports from unrestricted sources.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.19"]}, "severity": "Critical", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# List of high-risk ports
high_risk_ports = {
	20, 21, 22, 23, 25, 110, 135, 143, 445,
	1433, 1434, 3000, 3306, 3389, 4333,
	5000, 5432, 5500, 5601, 8080, 8088,
	8888, 9200, 9300,
}

# Get all security groups
security_groups = fugue.resources("aws_security_group")

# Check if a CIDR block is unrestricted
is_unrestricted_cidr(cidr) {
	cidr == "0.0.0.0/0"
}

is_unrestricted_cidr(cidr) {
	cidr == "::/0"
}

# Check if a port is in the high risk range
is_high_risk_port(from_port, to_port) {
	port := numbers.range(from_port, to_port)[_]
	high_risk_ports[port]
}

# Check if a rule allows unrestricted access to high risk ports
has_unrestricted_access(group) {
	rule := group.ingress[_]
	is_unrestricted_cidr(rule.cidr_blocks[_])
	is_high_risk_port(rule.from_port, rule.to_port)
}

has_unrestricted_access(group) {
	rule := group.ingress[_]
	is_unrestricted_cidr(rule.ipv6_cidr_blocks[_])
	is_high_risk_port(rule.from_port, rule.to_port)
}

# Allow security groups that don't have unrestricted access to high risk ports
policy[p] {
	group := security_groups[_]
	not has_unrestricted_access(group)
	p = fugue.allow_resource(group)
}

# Deny security groups that have unrestricted access to high risk ports
policy[p] {
	group := security_groups[_]
	has_unrestricted_access(group)
	p = fugue.deny_resource_with_message(
		group,
		"Security group allows unrestricted access (0.0.0.0/0 or ::/0) to high risk ports",
	)
}
