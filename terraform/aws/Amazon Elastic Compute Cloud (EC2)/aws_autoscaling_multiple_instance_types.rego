package rules.autoscaling_multiple_instance_types

import data.fugue

__rego__metadoc__ := {
	"id": "AutoScaling.6",
	"title": "Auto Scaling groups should use multiple instance types in multiple Availability Zones",
	"description": "This control checks whether Auto Scaling groups are configured to use multiple instance types across multiple Availability Zones for enhanced availability and resilience.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_AutoScaling.6"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all Auto Scaling groups
asg_groups = fugue.resources("aws_autoscaling_group")

# Helper to check if mixed instances policy is properly configured
has_valid_mixed_instances(asg) {
	policy := asg.mixed_instances_policy[_]
	overrides := policy.launch_template[_].override
	count(overrides) >= 2
}

# Helper to check if multiple AZs are configured
has_multiple_azs(asg) {
	zones := asg.availability_zones
	count(zones) >= 2
}

# Allow resources that meet both criteria
policy[p] {
	asg := asg_groups[_]
	has_valid_mixed_instances(asg)
	has_multiple_azs(asg)
	p = fugue.allow_resource(asg)
}

# Deny resources that don't meet the mixed instances requirement
policy[p] {
	asg := asg_groups[_]
	not has_valid_mixed_instances(asg)
	p = fugue.deny_resource_with_message(asg, "Auto Scaling group must use multiple instance types through mixed instances policy")
}

# Deny resources that don't meet the multiple AZ requirement
policy[p] {
	asg := asg_groups[_]
	not has_multiple_azs(asg)
	p = fugue.deny_resource_with_message(asg, "Auto Scaling group must use multiple Availability Zones")
}
