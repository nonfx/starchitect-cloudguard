package rules.elb_deletion_protection

import data.fugue

__rego__metadoc__ := {
	"id": "ELB.6",
	"title": "Application, Gateway, and Network Load Balancers should have deletion protection enabled",
	"description": "This control checks if deletion protection is enabled for Application, Gateway, and Network Load Balancers to prevent accidental deletion and ensure high availability.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ELB.6"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all load balancers
lbs = fugue.resources("aws_lb")

load_balancer_types := ["application", "network", "gateway"]

# Helper to check if load balancer type is valid
is_valid_lb_type(lb) {
	lb.load_balancer_type == load_balancer_types[_]
}

# Allow load balancers with deletion protection enabled
policy[p] {
	lb := lbs[_]
	is_valid_lb_type(lb)
	lb.enable_deletion_protection == true
	p = fugue.allow_resource(lb)
}

# Deny load balancers without deletion protection
policy[p] {
	lb := lbs[_]
	is_valid_lb_type(lb)
	lb.enable_deletion_protection == false
	p = fugue.deny_resource_with_message(lb, "Deletion protection must be enabled for Load Balancer")
}
