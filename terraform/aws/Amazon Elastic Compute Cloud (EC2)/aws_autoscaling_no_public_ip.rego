package rules.autoscaling_no_public_ip

import data.fugue

__rego__metadoc__ := {
	"id": "Autoscaling.5",
	"title": "Auto Scaling group launch configurations should not have Public IP addresses",
	"description": "Auto Scaling group launch configurations must disable public IP addresses for EC2 instances to enhance network security.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Autoscaling.5"]}, "severity": "High", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all launch configurations
launch_configs = fugue.resources("aws_launch_configuration")

# Helper to check if public IP is disabled
is_public_ip_disabled(config) {
	not config.associate_public_ip_address == true
}

# Allow if public IP is disabled
policy[p] {
	config := launch_configs[_]
	is_public_ip_disabled(config)
	p = fugue.allow_resource(config)
}

# Deny if public IP is enabled
policy[p] {
	config := launch_configs[_]
	not is_public_ip_disabled(config)
	p = fugue.deny_resource_with_message(config, "Auto Scaling group launch configuration must not assign public IP addresses to EC2 instances")
}
