package rules.iam_no_wildcard_actions

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "IAM.21",
	"title": "IAM customer managed policies should not allow wildcard actions for services",
	"description": "This control checks if IAM customer managed policies have wildcard actions for services. Using wildcard actions in IAM policies may grant users more privileges than needed.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_IAM.21"]}, "severity": "High"},
}

# Define resource type
resource_type := "MULTIPLE"

# Get all IAM policies
iam_policies = fugue.resources("aws_iam_policy")

# Helper function to check if a single action contains a wildcard
contains_wildcard(action) {
	is_string(action)
	regex.match(`:\*$|^\*$`, action)
}

# Helper function to check if any action in an array has a wildcard
has_wildcard_actions(actions) {
	is_array(actions)
	contains_wildcard(actions[_])
}

has_wildcard_actions(action) {
	is_string(action)
	contains_wildcard(action)
}

# Check if policy document contains wildcard actions
has_wildcard_policy(policy_doc) {
	statement := policy_doc.Statement[_]
	statement.Effect == "Allow"
	has_wildcard_actions(statement.Action)
}

# Allow policies without wildcard actions
policy[p] {
	policy := iam_policies[_]
	policy_doc := json.unmarshal(policy.policy)
	not has_wildcard_policy(policy_doc)
	p = fugue.allow_resource(policy)
}

# Deny policies with wildcard actions
policy[p] {
	policy := iam_policies[_]
	policy_doc := json.unmarshal(policy.policy)
	has_wildcard_policy(policy_doc)
	p = fugue.deny_resource_with_message(policy, "IAM policy contains wildcard actions for services which violates least privilege principle")
}
