package rules.aws_aurora_iam_roles_and_policies_created

import data.fugue

__rego__metadoc__ := {
	"id": "2.5",
	"title": "Ensure IAM Roles and Policies are Created",
	"description": "AWS Identity and Access Management (IAM) helps manage access to AWS resources. While you cannot directly associate IAM roles with Amazon Aurora instances, you can use IAM roles and policies to define which AWS IAM users and groups have management permissions for Amazon RDS resources and what actions they can perform",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_2.5"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

iam_roles = fugue.resources("aws_iam_role")

iam_policies = fugue.resources("aws_iam_policy")

iam_role_policy_attachments = fugue.resources("aws_iam_role_policy_attachment")

aurora_clusters = fugue.resources("aws_rds_cluster")

aurora_role_associations = fugue.resources("aws_rds_cluster_role_association")

role_has_rds_policy(role) {
	attachment := iam_role_policy_attachments[_]
	attachment.role == role.name
	policy := iam_policies[attachment.policy_arn]
	contains(lower(policy.name), "rds")
}

policy_is_rds_related(policy) {
	contains(lower(policy.name), "rds")
}

aurora_cluster_has_role_association(cluster) {
	association := aurora_role_associations[_]
	association.db_cluster_identifier == cluster.id
}

policy[p] {
	resource := iam_roles[_]
	role_has_rds_policy(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := iam_policies[_]
	policy_is_rds_related(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := aurora_clusters[_]
	aurora_cluster_has_role_association(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := aurora_role_associations[_]
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := iam_roles[_]
	not role_has_rds_policy(resource)
	p = fugue.deny_resource_with_message(resource, "IAM role does not have any RDS-related policies attached")
}

policy[p] {
	resource := iam_policies[_]
	not policy_is_rds_related(resource)
	p = fugue.deny_resource_with_message(resource, "IAM policy is not related to RDS/Aurora")
}

policy[p] {
	resource := aurora_clusters[_]
	not aurora_cluster_has_role_association(resource)
	p = fugue.deny_resource_with_message(resource, "Aurora DB cluster does not have an IAM role associated")
}
