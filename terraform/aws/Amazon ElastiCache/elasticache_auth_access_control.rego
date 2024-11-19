package rules.elasticache_auth_access_control

import data.fugue

__rego__metadoc__ := {
	"id": "5.8",
	"title": "Ensure Authentication and Access Control is Enabled",
	"description": "Individual creates IAM roles that would give specific permission to what the user can and cannot do within that database. The Access Control List (ACLs) allows only specific individuals to access the resources",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_5.8"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

elasticache_clusters = fugue.resources("aws_elasticache_cluster")

iam_roles = fugue.resources("aws_iam_role")

iam_policies = fugue.resources("aws_iam_policy")

iam_role_policy_attachments = fugue.resources("aws_iam_role_policy_attachment")

has_iam_role(cluster) {
	count(iam_roles) > 0
}

has_iam_policy(cluster) {
	count(iam_policies) > 0
}

has_iam_role_policy_attachment(cluster) {
	count(iam_role_policy_attachments) > 0
}

is_full_admin_policy(policy_resource) {
	policy := json.unmarshal(policy_resource.policy)
	statement := policy.Statement[_]
	statement.Effect == "Allow"
	actions = as_array(statement.Action[_])
	action = actions[_]
	contains(action, "*")
}

policy[p] {
	cluster := elasticache_clusters[_]
	has_iam_role(cluster)
	has_iam_policy(cluster)
	has_iam_role_policy_attachment(cluster)
	policy := iam_policies[_]
	not is_full_admin_policy(policy)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := elasticache_clusters[_]
	not has_iam_role(cluster)
	msg := sprintf("ElastiCache cluster '%s' does not have an associated IAM role", [cluster.cluster_id])
	p = fugue.deny_resource_with_message(cluster, msg)
}

policy[p] {
	cluster := elasticache_clusters[_]
	not has_iam_policy(cluster)
	msg := sprintf("ElastiCache cluster '%s' does not have an associated IAM policy", [cluster.cluster_id])
	p = fugue.deny_resource_with_message(cluster, msg)
}

policy[p] {
	cluster := elasticache_clusters[_]
	not has_iam_role_policy_attachment(cluster)
	msg := sprintf("ElastiCache cluster '%s' does not have an IAM role policy attachment", [cluster.cluster_id])
	p = fugue.deny_resource_with_message(cluster, msg)
}

policy[p] {
	cluster := elasticache_clusters[_]
	has_iam_policy(cluster)
	policy := iam_policies[_]
	is_full_admin_policy(policy)
	msg := sprintf("ElastiCache cluster '%s' has an IAM policy with full admin access", [cluster.cluster_id])
	p = fugue.deny_resource_with_message(cluster, msg)
}

as_array(x) = [x] {
	not is_array(x)
}
