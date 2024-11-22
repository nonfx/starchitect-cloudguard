package rules.security_group_authorized_ports

import data.fugue

__rego__metadoc__ := {
	"id": "EC2.18",
	"title": "Security groups should only allow unrestricted incoming traffic for authorized ports",
	"description": "Security groups should only allow unrestricted incoming traffic on authorized ports to protect network security.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.18"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Default authorized ports if no custom values provided
default_authorized_tcp_ports = [80, 443]

# Get all security groups
security_groups = fugue.resources("aws_security_group")

# Helper to check if CIDR is unrestricted
is_unrestricted_cidr(cidr) {
	cidr == "0.0.0.0/0"
}

# Helper to check if port is authorized
is_authorized_port(port) {
	some i
	port == default_authorized_tcp_ports[i]
}

# Helper to check if ingress rule has unauthorized unrestricted access
has_unauthorized_access(rule) {
	some i
	cidr := rule.cidr_blocks[i]
	is_unrestricted_cidr(cidr)
	rule.protocol == "tcp"
	not is_authorized_port(rule.from_port)
}

# Check security group ingress rules
check_security_group(sg) {
	some i
	rule := sg.ingress[i]
	has_unauthorized_access(rule)
}

# Allow if no unauthorized unrestricted access
policy[p] {
	sg := security_groups[_]
	not check_security_group(sg)
	p = fugue.allow_resource(sg)
}

# Deny if unauthorized unrestricted access found
policy[p] {
	sg := security_groups[_]
	check_security_group(sg)
	p = fugue.deny_resource_with_message(
		sg,
		sprintf("Security group '%s' allows unrestricted access on unauthorized ports", [sg.name]),
	)
}
