package rules.aws_default_security_group

import data.fugue

resource_type := "MULTIPLE"

__rego__metadoc__ := {
	"id": "5.4",
	"title": "Ensure the default security group of every VPC restricts all traffic",
	"description": "A VPC comes with a default security group whose initial settings deny all inbound traffic, allow all outbound traffic, and allow all traffic between instances assigned to the security group. If you don't specify a security group when you launch an instance, the instance is automatically assigned to this default security group. Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that the default security group restrict all traffic.",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_5.4"]},"severity":"Low","author":"Starchitect Agent"},
}

policy[j] {
	vpcs[id] = vpc
	valid_vpc(vpc)
	j = fugue.allow_resource(vpc)
}

policy[j] {
	vpcs[id] = vpc
	not valid_vpc(vpc)
	j = fugue.deny_resource(vpc)
}

vpcs = fugue.resources("aws_vpc")

security_groups[id] = sg {
	sgs = fugue.resources("aws_security_group")
	sg = sgs[id]
}

security_groups[id] = sg {
	fugue.input_resource_types.aws_default_security_group
	sgs = fugue.resources("aws_default_security_group")
	sg = sgs[id]
}

is_default_security_group_for(sg, vpc) {
	sg.id == vpc.default_security_group_id
}

is_default_security_group_for(sg, vpc) {
	sg._type == "aws_default_security_group"
}

valid_vpc(vpc) {
	default_sg = security_groups[_]
	is_default_security_group_for(default_sg, vpc)
	restricts_ingress_traffic(default_sg)
	restricts_egress_traffic(default_sg)
}

has_ingress(sg) {
	_ = sg.ingress[_]
}

restricts_ingress_traffic(sg) {
	# There are no ingress rules.
	not has_ingress(sg)
}

restricts_ingress_traffic(sg) {
	# Or, there is a single ingress rule that point to itself.
	count(sg.ingress) == 1
	ig = sg.ingress[_]
	object.get(ig, "cidr_blocks", []) == []
	ig.self == true
}

has_egress(sg) {
	_ = sg.egress[_]
}

restricts_egress_traffic(sg) {
	# There are no egress rules.
	not has_egress(sg)
}

restricts_egress_traffic(sg) {
	# Or there is a single egress rule only allows traffic to "127.0.0.1".
	count(sg.egress) == 1
	eg = sg.egress[_]
	eg.cidr_blocks == ["127.0.0.1/32"]
}
