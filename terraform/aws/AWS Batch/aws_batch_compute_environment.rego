package rules.aws_batch_compute_environment

import data.fugue

__rego__metadoc__ := {
	"id": "5.2",
	"title": "Ensure Batch roles are configured for cross-service confused deputy prevention",
	"description": "The Cross-service confused deputy problem is a security issue where an entity that doesn't have permission to perform an action can coerce a more-privileged entity to perform the action",
	"custom": {"severity":"Medium","controls":{"CIS-AWS-Compute-Services-Benchmark_v1.0.0":["CIS-AWS-Compute-Services-Benchmark_v1.0.0_5.2"]},"author":"Starchitect Agent"},
}

# Mark the rule to observe multiple resource types
resource_type := "MULTIPLE"

# Query for AWS Batch Compute Environments
batch_compute_environments = fugue.resources("aws_batch_compute_environment")

# Query for IAM Roles
iam_roles = fugue.resources("aws_iam_role")

# Function to check if the service role is properly configured
has_valid_service_role(compute_env) {
	service_role_arn := compute_env.service_role
	role := iam_roles[service_role_arn]
	role_policy := json.unmarshal(role.assume_role_policy)
	role_policy.Statement[0].Condition.StringEquals["aws:SourceAccount"] != ""
	role_policy.Statement[0].Condition.ArnLike["aws:SourceArn"] != ""
}

# Policy rule to validate compute environments and their service roles
policy[p] {
	compute_env := batch_compute_environments[_]
	has_valid_service_role(compute_env)
	p = fugue.allow_resource(compute_env)
}

policy[p] {
	compute_env := batch_compute_environments[_]
	has_valid_service_role(compute_env)
	p = fugue.allow_resource(compute_env)
}

policy[p] {
	compute_env := batch_compute_environments[_]
	not has_valid_service_role(compute_env)
	p = fugue.deny_resource_with_message(compute_env, sprintf("Compute Environment %s has an incorrect service role policy.", [compute_env.compute_environment_name]))
}
