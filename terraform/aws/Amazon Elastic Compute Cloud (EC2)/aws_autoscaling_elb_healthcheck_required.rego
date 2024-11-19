package rules.autoscaling_elb_healthcheck_required

import data.fugue

__rego__metadoc__ := {
	"id": "AutoScaling.1",
	"title": "Auto Scaling groups associated with a load balancer should use ELB health checks",
	"description": "This control checks whether Auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing (ELB) health checks. The control fails if an Auto Scaling group with an attached load balancer is not using ELB health checks.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_AutoScaling.1"]}, "severity": "Low", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all Auto Scaling groups
asg_groups = fugue.resources("aws_autoscaling_group")

# Helper function to check if ASG has load balancer attached
has_load_balancer(asg) {
	count(asg.load_balancers) > 0
}

has_load_balancer(asg) {
	count(asg.target_group_arns) > 0
}

# Helper function to check if ELB health check is enabled
has_elb_healthcheck(asg) {
	asg.health_check_type == "ELB"
}

# Allow ASG if it has no load balancer attached
policy[p] {
	asg := asg_groups[_]
	not has_load_balancer(asg)
	p = fugue.allow_resource(asg)
}

# Allow ASG if it has load balancer and ELB health check
policy[p] {
	asg := asg_groups[_]
	has_load_balancer(asg)
	has_elb_healthcheck(asg)
	p = fugue.allow_resource(asg)
}

# Deny ASG if it has load balancer but no ELB health check
policy[p] {
	asg := asg_groups[_]
	has_load_balancer(asg)
	not has_elb_healthcheck(asg)
	p = fugue.deny_resource_with_message(asg, "Auto Scaling group with attached load balancer must use ELB health checks")
}
