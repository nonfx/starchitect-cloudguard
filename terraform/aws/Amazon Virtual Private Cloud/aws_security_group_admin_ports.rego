package rules.aws_security_group_admin_ports

import data.fugue

__rego__metadoc__ := {
	"id": "5.2",
	"title": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports such as 22 and 3389 (Remote Desktop Protocol)",
	"description": "Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to remote server administration ports such as 22 & 3389",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": [
			"CIS-AWS-Foundations-Benchmark_v3.0.0_5.2",
			"CIS-AWS-Foundations-Benchmark_v3.0.0_5.3",
		]},
		"severity": "Low",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

security_groups = fugue.resources("aws_security_group")

policy[p] {
	sg := security_groups[_]
	ingress := sg.ingress[_]
	is_open_admin_port(ingress)
	p = fugue.deny_resource_with_message(sg, "Security group allows unrestricted access to ports other than 80 and 443")
}

policy[p] {
	sg := security_groups[_]
	ingress := sg.ingress[_]
	not is_open_admin_port(ingress)
	p = fugue.allow_resource(sg)
}

# zero CIDR on ports other than 443 and 80
is_open_admin_port(rule) {
	rule_zero_cidr(rule)
	not is_port_80(rule)
	not is_port_443(rule)
}

is_port_80(rule) {
	rule.to_port == 80
	rule.from_port == 80
}

is_port_443(rule) {
	rule.to_port == 443
	rule.from_port == 443
}

# Does an ingress block have the zero ("0.0.0.0/0" or "::/0") CIDR?
rule_zero_cidr(rule) {
	zero_cidr(rule.cidr_blocks[_])
}

rule_zero_cidr(rule) {
	zero_cidr(rule.ipv6_cidr_blocks[_])
}

zero_cidr(cidr) {
	cidr == "0.0.0.0/0"
}

zero_cidr(cidr) {
	cidr == "::/0"
}
