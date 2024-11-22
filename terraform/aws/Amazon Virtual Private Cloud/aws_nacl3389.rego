package rules.aws_nacl_3389

import data.aws.vpc.nacl_library as lib
import data.fugue

__rego__metadoc__ := {
	"id": "5.1",
	"title": "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration port 3389",
	"description": "The Network Access Control List (NACL) function provide stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to remote server administration port 3389",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_5.1"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

nacls = fugue.resources("aws_network_acl")

# Return true if deny rule is lower (aka takes precedence)
lower_deny(deny, allow) {
	deny < allow
}

# Good nacl rules either:
#   - Have no ALLOW rules
#   - Have DENY rules before any ALLOW rules
is_good_nacl(nacl) {
	allow = lib.lowest_allow_ingress_zero_cidr_by_port(nacl, 3389)
	deny = lib.lowest_deny_ingress_zero_cidr_by_port(nacl, 3389)
	lower_deny(deny, allow)
}

is_good_nacl(nacl) {
	not lib.lowest_allow_ingress_zero_cidr_by_port(nacl, 3389)
}

policy[j] {
	nacl = nacls[_]
	is_good_nacl(nacl)
	j = fugue.allow_resource(nacl)
}

policy[j] {
	nacl = nacls[_]
	not is_good_nacl(nacl)
	j = fugue.deny_resource(nacl)
}
