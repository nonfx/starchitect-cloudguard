package rules.aws_rds_security_groups_configured

import data.fugue

__rego__metadoc__ := {
	"id": "3.4",
	"title": "Ensure to Configure Security Groups for RDS Instances",
	"description": "Configuring security groups benefits the user because it helps manage networks within the database and gives only certain permission for traffic that leaves and enters the database.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_3.4"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

rds_instances = fugue.resources("aws_db_instance")

security_groups = fugue.resources("aws_security_group")

# Check if an RDS instance has associated security groups
has_security_groups(instance) {
	count(instance.vpc_security_group_ids) > 0
}

# Check if a security group has inbound rules
has_inbound_rules(sg) {
	count(sg.ingress) > 0
}

# Check if a security group has outbound rules
has_outbound_rules(sg) {
	count(sg.egress) > 0
}

# Validate security group configuration
valid_security_group(sg_id) {
	sg := security_groups[sg_id]
	has_inbound_rules(sg)
	has_outbound_rules(sg)
}

# Check if an RDS instance has properly configured security groups
instance_has_valid_security_groups(instance) {
	sg_id := instance.vpc_security_group_ids[_]
	valid_security_group(sg_id)
}

policy[p] {
	instance := rds_instances[_]
	has_security_groups(instance)
	instance_has_valid_security_groups(instance)
	p := fugue.allow_resource(instance)
}

policy[p] {
	instance := rds_instances[_]
	not has_security_groups(instance)
	msg := sprintf("RDS instance '%s' does not have any associated security groups", [instance.id])
	p := fugue.deny_resource_with_message(instance, msg)
}

policy[p] {
	instance := rds_instances[_]
	has_security_groups(instance)
	not instance_has_valid_security_groups(instance)
	msg := sprintf("RDS instance '%s' has associated security groups, but they are not properly configured", [instance.id])
	p := fugue.deny_resource_with_message(instance, msg)
}
