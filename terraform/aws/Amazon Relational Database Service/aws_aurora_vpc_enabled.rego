package rules.aws_rds_in_vpc

import data.fugue

__rego__metadoc__ := {
	"id": "2.1",
	"title": "Ensure Amazon VPC (Virtual Private Cloud) has been created",
	"description": "Amazon VPCs allow you to launch AWS resources into a defined virtual network, providing network isolation and controlling inbound and outbound traffic.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_2.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

aurora_instances := fugue.resources("aws_rds_cluster")

vpcs := fugue.resources("aws_vpc")

db_subnet_groups := fugue.resources("aws_db_subnet_group")

# Check if VPC exists
vpc_exists {
	count(vpcs) > 0
}

# Check if instance is in a VPC
instance_in_vpc(instance) {
	instance.db_subnet_group_name != null
}

# Check if the db_subnet_group is associated with an existing VPC
subnet_group_in_valid_vpc(instance) {
	group_name := instance.db_subnet_group_name
	group := db_subnet_groups[_]
	group.name == group_name
	count(group.subnet_ids) > 0
}

policy[p] {
	vpc_exists
	instance := aurora_instances[_]
	instance_in_vpc(instance)
	subnet_group_in_valid_vpc(instance)
	p := fugue.allow_resource(instance)
}

policy[p] {
	not vpc_exists
	instance := aurora_instances[_]
	msg := "No VPC exists. Create a VPC before deploying aurora instances."
	p := fugue.deny_resource_with_message(instance, msg)
}

policy[p] {
	vpc_exists
	instance := aurora_instances[_]
	not instance_in_vpc(instance)
	msg := sprintf("Aurora instance '%s' is not deployed in a VPC. Ensure it is associated with a DB subnet group.", [instance.identifier])
	p := fugue.deny_resource_with_message(instance, msg)
}

policy[p] {
	vpc_exists
	instance := aurora_instances[_]
	instance_in_vpc(instance)
	not subnet_group_in_valid_vpc(instance)
	msg := sprintf("Aurora instance '%s' is associated with a DB subnet group that is not in a valid VPC or has no subnets.", [instance.identifier])
	p := fugue.deny_resource_with_message(instance, msg)
}
