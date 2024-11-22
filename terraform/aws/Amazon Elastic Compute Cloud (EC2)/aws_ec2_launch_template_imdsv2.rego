package rules.ec2_launch_template_imdsv2

import data.fugue

__rego__metadoc__ := {
	"id": "EC2.170",
	"title": "EC2 launch templates should use Instance Metadata Service Version 2 (IMDSv2)",
	"description": "This control checks if EC2 launch templates are configured to use IMDSv2. IMDSv2 provides enhanced security through token-based authentication for instance metadata requests.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.170"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all EC2 launch templates
launch_templates = fugue.resources("aws_launch_template")

# Helper to check if IMDSv2 is required
is_imdsv2_required(template) {
	template.metadata_options[_].http_tokens == "required"
}

# Allow templates that require IMDSv2
policy[p] {
	template := launch_templates[_]
	is_imdsv2_required(template)
	p = fugue.allow_resource(template)
}

# Deny templates that don't require IMDSv2
policy[p] {
	template := launch_templates[_]
	not is_imdsv2_required(template)
	p = fugue.deny_resource_with_message(template, "EC2 launch template must require IMDSv2 by setting http_tokens to 'required' in metadata_options")
}
