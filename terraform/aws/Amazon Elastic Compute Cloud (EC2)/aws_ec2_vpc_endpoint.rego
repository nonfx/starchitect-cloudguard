package rules.ec2_vpc_endpoint

import data.fugue

__rego__metadoc__ := {
	"id": "EC2.10",
	"title": "Amazon EC2 should be configured to use VPC endpoints that are created for the Amazon EC2 service",
	"description": "This control checks if VPC endpoints are created for the EC2 service in VPCs that contain EC2 instances. The control fails if a VPC containing EC2 instances does not have an EC2 VPC endpoint.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.10"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all resources
ec2_instances = fugue.resources("aws_instance")

vpc_endpoints = fugue.resources("aws_vpc_endpoint")

vpcs = fugue.resources("aws_vpc")

# Helper to check if VPC has EC2 endpoint
has_ec2_endpoint(vpc_id) {
	endpoint := vpc_endpoints[_]
	endpoint.vpc_id == vpc_id
	endpoint.service_name == "com.amazonaws.region.ec2"
	endpoint.vpc_endpoint_type == "Interface"
}

# Helper to get VPC ID for an instance
get_vpc_id(instance) = vpc_id {
	vpc := vpcs[_]
	instance.subnet_id == vpc.subnet_ids[_]
	vpc_id := vpc.id
}

# Policy for EC2 instances
policy[p] {
	instance := ec2_instances[_]
	vpc_id := get_vpc_id(instance)
	has_ec2_endpoint(vpc_id)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := ec2_instances[_]
	vpc_id := get_vpc_id(instance)
	not has_ec2_endpoint(vpc_id)
	p = fugue.deny_resource_with_message(instance, "EC2 instance is in a VPC without an EC2 VPC endpoint")
}

# Policy for VPC endpoints
policy[p] {
	endpoint := vpc_endpoints[_]
	endpoint.service_name == "com.amazonaws.region.ec2"
	endpoint.vpc_endpoint_type == "Interface"
	p = fugue.allow_resource(endpoint)
}
