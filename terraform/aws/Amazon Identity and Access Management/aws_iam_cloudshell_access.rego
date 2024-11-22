package rules.aws_cloudshell_access

import data.fugue

__rego__metadoc__ := {
	"id": "1.22",
	"title": "Ensure access to AWSCloudShellFullAccess is restricted",
	"description": "AWS CloudShell is a convenient way of running CLI commands against AWS services; a managed IAM policy ('AWSCloudShellFullAccess') provides full access to CloudShell, which allows file upload and download capability between a user's local system and the CloudShell environment. Within the CloudShell environment a user has sudo permissions, and can access the internet. So it is feasible to install file transfer software (for example) and move data from CloudShell to external internet servers.",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_1.22"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

iam_users = fugue.resources("aws_iam_user")

# Define the AWSCloudShellFullAccess policy ARN
cloudshell_full_access_policy_arn = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"

# Get all IAM role policy attachments
role_policy_attachments = fugue.resources("aws_iam_role_policy_attachment")

# Get all IAM user policy attachments
user_policy_attachments = fugue.resources("aws_iam_user_policy_attachment")

# Get all IAM group policy attachments
group_policy_attachments = fugue.resources("aws_iam_group_policy_attachment")

# Check if the AWSCloudShellFullAccess policy is attached to any role
role_has_cloudshell_full_access(role_policy) {
	role_policy.policy_arn == cloudshell_full_access_policy_arn
}

# Check if the AWSCloudShellFullAccess policy is attached to any user
user_has_cloudshell_full_access(user_policy) {
	user_policy.policy_arn == cloudshell_full_access_policy_arn
}

# Check if the AWSCloudShellFullAccess policy is attached to any group
group_has_cloudshell_full_access(group_policy) {
	group_policy.policy_arn == cloudshell_full_access_policy_arn
}

# Ensure access to AWSCloudShellFullAccess is restricted
restricted_access_to_cloudshell {
	user_has_cloudshell_full_access(user_policy_attachments[_])
}

restricted_access_to_cloudshell {
	role_has_cloudshell_full_access(role_policy_attachments[_])
}

restricted_access_to_cloudshell {
	group_has_cloudshell_full_access(group_policy_attachments[_])
}

policy[p] {
	user = iam_users[_]
	restricted_access_to_cloudshell
	p = fugue.deny_resource(user)
}

policy[p] {
	user = iam_users[_]
	not restricted_access_to_cloudshell
	p = fugue.allow_resource(user)
}
