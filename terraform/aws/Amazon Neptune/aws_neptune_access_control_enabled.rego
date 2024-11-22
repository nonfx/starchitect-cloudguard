package rules.aws_neptune_access_control_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "9.4.b",
	"title": "Ensure Authentication and Access Control is Enabled - access control",
	"description": "This helps ensure that there are specific IAM roles and policies that are given the necessary information within a Neptune DB cluster to operate as needed.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_9.4"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

neptune_clusters := fugue.resources("aws_neptune_cluster")

iam_roles := fugue.resources("aws_iam_role")

iam_policies := fugue.resources("aws_iam_policy")

iam_role_policies := fugue.resources("aws_iam_role_policy")

iam_user_policies := fugue.resources("aws_iam_user_policy")

iam_group_policies := fugue.resources("aws_iam_group_policy")

as_array(x) = [x] {
	not is_array(x)
}

else = x

fgac_not_followed(policy_resource, cluster) {
	policy := json.unmarshal(policy_resource.policy)
	statement := policy.Statement[_]
	statement.Effect == "Allow"
	resources := as_array(statement.Resource)
	resource := resources[_]
	contains(resource, cluster.cluster_identifier)
	actions := as_array(statement.Action)
	action := actions[_]
	action == "*"
}

fgac_not_followed(policy_resource, cluster) {
	policy := json.unmarshal(policy_resource.policy)
	statement := policy.Statement[_]
	statement.Effect == "Allow"
	resources := as_array(statement.Resource)
	resource := resources[_]
	contains(resource, cluster.cluster_identifier)
	actions := as_array(statement.Action)
	action := actions[_]
	action == "neptune-db:*"
}

cluster_has_associated_role(cluster, roles) {
	role := roles[_]
	contains(cluster.iam_roles[_], role.id)
}

policy[p] {
	cluster := neptune_clusters[_]
	cluster_has_associated_role(cluster, iam_roles)
	roles_with_access := [role | role := iam_roles[_]; not fgac_not_followed(role, cluster)]
	count(roles_with_access) > 0
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	not cluster_has_associated_role(cluster, iam_roles)
	p = fugue.deny_resource_with_message(cluster, "Neptune cluster does not have any associated IAM roles for access control")
}

# Check IAM policies
policy[p] {
	cluster := neptune_clusters[_]
	iam_policy := iam_policies[_]
	not fgac_not_followed(iam_policy, cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	iam_policy := iam_policies[_]
	fgac_not_followed(iam_policy, cluster)
	msg := sprintf("Access Control is not properly implemented on IAM policy for Neptune cluster '%s'", [cluster.cluster_identifier])
	p = fugue.deny_resource_with_message(cluster, msg)
}

# Check IAM role policies
policy[p] {
	cluster := neptune_clusters[_]
	iam_role_policy := iam_role_policies[_]
	not fgac_not_followed(iam_role_policy, cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	iam_role_policy := iam_role_policies[_]
	fgac_not_followed(iam_role_policy, cluster)
	msg := sprintf("Access Control is not properly implemented on IAM role policy for Neptune cluster '%s'", [cluster.cluster_identifier])
	p = fugue.deny_resource_with_message(cluster, msg)
}

# Check IAM user policies
policy[p] {
	cluster := neptune_clusters[_]
	iam_user_policy := iam_user_policies[_]
	not fgac_not_followed(iam_user_policy, cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	iam_user_policy := iam_user_policies[_]
	fgac_not_followed(iam_user_policy, cluster)
	msg := sprintf("Access Control is not properly implemented on IAM user policy for Neptune cluster '%s'", [cluster.cluster_identifier])
	p = fugue.deny_resource_with_message(cluster, msg)
}

# Check IAM group policies
policy[p] {
	cluster := neptune_clusters[_]
	iam_group_policy := iam_group_policies[_]
	not fgac_not_followed(iam_group_policy, cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := neptune_clusters[_]
	iam_group_policy := iam_group_policies[_]
	fgac_not_followed(iam_group_policy, cluster)
	msg := sprintf("Access Control is not properly implemented on IAM group policy for Neptune cluster '%s'", [cluster.cluster_identifier])
	p = fugue.deny_resource_with_message(cluster, msg)
}
