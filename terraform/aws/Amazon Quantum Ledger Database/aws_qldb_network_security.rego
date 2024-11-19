package rules.aws_qldb_network_security

import data.fugue
import future.keywords

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "11.2",
	"title": "Ensure Network Access is Secure for QLDB",
	"description": "By applying certain network access such as Virtual Private Cloud (VPC) it protects the private network that has been established from any external networks from interfering. It allows internal networks to communicate with one another with the network that has been established. The Access Control List (ACLs) allows only specific individuals to access the resources. Also, by monitoring and logging the activity within the database it helps the individual know what is being logged within the activity and determine what next step they should take to address it.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_11.2"]}},
}

resource_type := "MULTIPLE"

qldb_ledgers := fugue.resources("aws_qldb_ledger")

vpcs := fugue.resources("aws_vpc")

security_groups := fugue.resources("aws_security_group")

vpc_endpoints := fugue.resources("aws_vpc_endpoint")

network_acls := fugue.resources("aws_network_acl")

cloudwatch_log_groups := fugue.resources("aws_cloudwatch_log_group")

qldb_in_vpc(ledger) if {
	ledger.deletion_protection == true
}

has_qldb_vpc_endpoint(vpc_id) if {
	some endpoint in vpc_endpoints
	endpoint.vpc_id == vpc_id
	regex.match("com\\.amazonaws\\.[a-z0-9-]", endpoint.service_name)
}

has_secure_sg_rules(sg) if {
	some ingress in sg.ingress
	ingress.from_port <= 443
	ingress.to_port >= 443
	ingress.protocol == "tcp"
	count(ingress.cidr_blocks) > 0
	not any_cidr_block_open(ingress.cidr_blocks)
}

any_cidr_block_open(cidr_blocks) if {
	some cidr in cidr_blocks
	cidr == "0.0.0.0/0"
}

has_secure_nacl_rules(nacl) if {
	some ingress in nacl.ingress
	ingress.from_port <= 443
	ingress.to_port >= 443
	ingress.protocol == "tcp"
	ingress.cidr_block != "0.0.0.0/0"
}

has_logging_enabled(ledger) if {
	some log_group in cloudwatch_log_groups
	startswith(log_group.name, concat("", ["/aws/qldb/", ledger.name]))
}

policy contains p if {
	ledger := qldb_ledgers[_]
	qldb_in_vpc(ledger)
	vpc := vpcs[_]
	has_qldb_vpc_endpoint(vpc.id)
	sg := security_groups[_]
	sg.vpc_id == vpc.id
	has_secure_sg_rules(sg)
	nacl := network_acls[_]
	nacl.vpc_id == vpc.id
	has_secure_nacl_rules(nacl)
	has_logging_enabled(ledger)
	p = fugue.allow_resource(ledger)
}

policy contains p if {
	ledger := qldb_ledgers[_]
	not qldb_in_vpc(ledger)
	msg := sprintf("QLDB ledger '%s' is not deployed in a VPC or deletion protection is not enabled", [ledger.id])
	p = fugue.deny_resource_with_message(ledger, msg)
}

policy contains p if {
	ledger := qldb_ledgers[_]
	qldb_in_vpc(ledger)
	vpc := vpcs[_]
	not has_qldb_vpc_endpoint(vpc.id)
	msg := sprintf("VPC '%s' does not have a QLDB VPC endpoint", [vpc.id])
	p = fugue.deny_resource_with_message(vpc, msg)
}

policy contains p if {
	ledger := qldb_ledgers[_]
	qldb_in_vpc(ledger)
	vpc := vpcs[_]
	has_qldb_vpc_endpoint(vpc.id)
	sg := security_groups[_]
	sg.vpc_id == vpc.id
	not has_secure_sg_rules(sg)
	msg := sprintf("Security group '%s' does not have secure rules for QLDB access", [sg.id])
	p = fugue.deny_resource_with_message(sg, msg)
}

policy contains p if {
	ledger := qldb_ledgers[_]
	qldb_in_vpc(ledger)
	vpc := vpcs[_]
	has_qldb_vpc_endpoint(vpc.id)
	nacl := network_acls[_]
	nacl.vpc_id == vpc.id
	not has_secure_nacl_rules(nacl)
	msg := sprintf("Network ACL '%s' does not have secure rules for QLDB access", [nacl.id])
	p = fugue.deny_resource_with_message(nacl, msg)
}

policy contains p if {
	ledger := qldb_ledgers[_]
	not has_logging_enabled(ledger)
	msg := sprintf("QLDB ledger '%s' does not have logging enabled", [ledger.id])
	p = fugue.deny_resource_with_message(ledger, msg)
}
