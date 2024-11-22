package rules.redshift_restricted_port_access

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "Redshift.15",
	"title": "Redshift security groups should allow ingress on the cluster port only from restricted origins",
	"description": "This control checks if Redshift clusters have security groups that allow unrestricted access (0.0.0.0/0 or ::/0) to cluster ports. Security groups should restrict access to specific IP ranges following the principle of least privilege.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Redshift.15"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all relevant resources
redshift_clusters = fugue.resources("aws_redshift_cluster")

security_groups = fugue.resources("aws_security_group")

security_group_rules = fugue.resources("aws_security_group_rule")

# Check if CIDR is open to the internet
is_cidr_open(cidr) {
	cidr == "0.0.0.0/0"
}

is_cidr_open(cidr) {
	cidr == "::/0"
}

# Check if security group has unrestricted access through ingress rules
has_unrestricted_ingress_rule(sg) {
	some ingress in sg.ingress
	some cidr in ingress.cidr_blocks
	is_cidr_open(cidr)
}

has_unrestricted_ingress_rule(sg) {
	some ingress in sg.ingress
	some cidr in ingress.ipv6_cidr_blocks
	is_cidr_open(cidr)
}

# Check if security group has unrestricted access through security group rules
has_unrestricted_sg_rule(sg) {
	rule := security_group_rules[_]
	rule.security_group_id == sg.id
	rule.type == "ingress"
	some cidr in rule.cidr_blocks
	is_cidr_open(cidr)
}

has_unrestricted_sg_rule(sg) {
	rule := security_group_rules[_]
	rule.security_group_id == sg.id
	rule.type == "ingress"
	some cidr in rule.ipv6_cidr_blocks
	is_cidr_open(cidr)
}

# Check if security group has any unrestricted access
has_unrestricted_access(sg) {
	has_unrestricted_ingress_rule(sg)
}

has_unrestricted_access(sg) {
	has_unrestricted_sg_rule(sg)
}

# Allow clusters with restricted security groups
policy[p] {
	cluster := redshift_clusters[_]
	sg_id := cluster.vpc_security_group_ids[_]
	sg := security_groups[_]
	sg.id == sg_id
	not has_unrestricted_access(sg)
	p = fugue.allow_resource(cluster)
}

# Deny clusters with unrestricted security groups
policy[p] {
	cluster := redshift_clusters[_]
	sg_id := cluster.vpc_security_group_ids[_]
	sg := security_groups[_]
	sg.id == sg_id
	has_unrestricted_access(sg)
	p = fugue.deny_resource_with_message(cluster, "Redshift cluster security group allows unrestricted access (0.0.0.0/0 or ::/0) to cluster ports")
}
