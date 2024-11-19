package rules.aws_ec2_systems_manager

import data.fugue

__rego__metadoc__ := {
	"author": "rajat@nonfx.com",
	"id": "2.9",
	"title": "Ensure use of AWS Systems Manager to manage EC2 instances",
	"description": "An inventory and management of Amazon Elastic Compute Cloud (Amazon EC2) instances is made possible with AWS Systems Manager.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.9"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all EC2 instances
ec2_instances := fugue.resources("aws_instance")

# Get all IAM instance profiles
iam_instance_profiles := fugue.resources("aws_iam_instance_profile")

# Get all IAM roles
iam_roles := fugue.resources("aws_iam_role")

# Get all IAM role policy attachments
iam_role_policy_attachments := fugue.resources("aws_iam_role_policy_attachment")

# Check if the instance has an IAM instance profile attached
has_instance_profile(instance) {
	instance.iam_instance_profile != null
}

# Check if the IAM role has the AmazonSSMManagedInstanceCore policy attached
has_ssm_policy(role_name) {
	attachment := iam_role_policy_attachments[_]
	attachment.role == role_name
	attachment.policy_arn == "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Validate that the instance profile is associated with a role that has the SSM policy
valid_instance_profile(instance) {
	profile_name := instance.iam_instance_profile
	profile_key := sprintf("aws_iam_instance_profile.%s", [instance.iam_instance_profile])
	profile := iam_instance_profiles[profile_key]
	role_name := profile.role
	role_key := sprintf("aws_iam_role.%s", [role_name])
	role := iam_roles[role_key]
	has_ssm_policy(role.name)
}

# Deny instances without an IAM instance profile
policy[p] {
	instance := ec2_instances[_]
	not has_instance_profile(instance)
	msg := sprintf("EC2 instance '%s' does not have an IAM instance profile attached", [instance.id])
	p = fugue.deny_resource_with_message(instance, msg)
}

# Deny instances with an instance profile but without the SSM policy
policy[p] {
	instance := ec2_instances[_]
	not has_instance_profile(instance)
	not valid_instance_profile(instance)
	msg := sprintf("EC2 instance '%s' has an IAM instance profile, but it's not associated with a role that has the AmazonSSMManagedInstanceCore policy", [instance.id])
	p = fugue.deny_resource_with_message(instance, msg)
}

# Allow instances with a valid instance profile and SSM policy
policy[p] {
	instance := ec2_instances[_]
	has_instance_profile(instance)
	valid_instance_profile(instance)
	p = fugue.allow_resource(instance)
}
