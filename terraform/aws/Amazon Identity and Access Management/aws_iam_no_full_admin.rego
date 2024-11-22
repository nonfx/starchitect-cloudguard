package rules.aws_iam_no_full_admin

import data.aws.iam.policy_document_library as lib
import data.fugue

__rego__metadoc__ := {
	"id": "1.16",
	"title": "Ensure IAM policies that allow full *:* administrative privileges are not attached",
	"description": "IAM policies are the means by which privileges are granted to users, groups, or roles. It is recommended and considered a standard security advice to grant least privilege -that is, granting only the permissions required to perform a task. Determine what users need to do and then craft policies for them that let the users perform only those tasks, instead of allowing full administrative privileges.",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_1.16"]},
		"severity": "High",
		"author": "Starchitect Agent",
	},
}

# All policy objects that have an ID and a `policy` field containing a JSON
# string.
policies[id] = p {
	ps = fugue.resources("aws_iam_policy")
	p = ps[id]
}

policies[id] = p {
	ps = fugue.resources("aws_iam_group_policy")
	p = ps[id]
}

policies[id] = p {
	ps = fugue.resources("aws_iam_role_policy")
	p = ps[id]
}

policies[id] = p {
	ps = fugue.resources("aws_iam_user_policy")
	p = ps[id]
}

# All wildcard policies.
wildcard_policies := {id: p |
	p = policies[id]
	is_wildcard_policy(p)
}

# Determine if a policy is a "wildcard policy".  A wildcard policy is defined as
# a policy having a statement that has all of:
#
# - Effect: Allow
# - Resource: "*"
# - Action: "*"
is_wildcard_policy(pol) {
	doc = lib.to_policy_document(pol.policy)
	statements = as_array(doc.Statement)
	statement = statements[_]

	statement.Effect == "Allow"

	resources = as_array(statement.Resource)
	resource = resources[_]
	resource == "*"

	actions = as_array(statement.Action)
	action = actions[_]
	action == "*"
}

# Looking for AWS-managed IAM policies in AWS commercial regions
aws_managed_policy(pol) {
	policy_arn = pol.arn
	prefix = "arn:aws:iam::aws:policy/"
	startswith(policy_arn, prefix)
}

# Judge policies and wildcard policies.
resource_type := "MULTIPLE"

policy[j] {
	pol = wildcard_policies[id]
	not aws_managed_policy(pol)
	j = fugue.deny_resource(pol)
}

policy[j] {
	pol = policies[id]
	not wildcard_policies[id]
	j = fugue.allow_resource(pol)
}

# Utility: turns anything into an array, if it's not an array already.
as_array(x) = [x] {
	not is_array(x)
}

else = x
