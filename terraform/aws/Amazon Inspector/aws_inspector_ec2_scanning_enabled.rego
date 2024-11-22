package rules.inspector_ec2_scanning_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "Inspector.1",
	"title": "Amazon Inspector EC2 scanning should be enabled",
	"description": "This control checks if Amazon Inspector EC2 scanning is enabled. Inspector helps identify security vulnerabilities and network accessibility issues in EC2 instances.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Inspector.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Inspector2 enabler resources
inspector_enablers = fugue.resources("aws_inspector2_enabler")

# Helper to check if EC2 scanning is enabled
is_ec2_scanning_enabled(enabler) {
	enabler.account_ids[_] != ""
	enabler.resource_types[_] == "EC2"
}

# Allow if Inspector2 EC2 scanning is enabled
policy[p] {
	count(inspector_enablers) > 0
	enabler := inspector_enablers[_]
	is_ec2_scanning_enabled(enabler)
	p = fugue.allow_resource(enabler)
}

# Deny if Inspector2 EC2 scanning is disabled
policy[p] {
	count(inspector_enablers) > 0
	enabler := inspector_enablers[_]
	not is_ec2_scanning_enabled(enabler)
	p = fugue.deny_resource_with_message(enabler, "Amazon Inspector EC2 scanning must be enabled for vulnerability assessment")
}

# Deny if no Inspector2 enabler exists
policy[p] {
	count(inspector_enablers) == 0
	p = fugue.missing_resource_with_message("aws_inspector2_enabler", "No Amazon Inspector enabler found - Inspector EC2 scanning must be enabled")
}
