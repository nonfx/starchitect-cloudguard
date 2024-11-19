package rules.rds_instances_in_vpc

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.18",
	"title": "RDS instances should be deployed in a VPC",
	"description": "This control checks whether RDS instances are deployed in a VPC. The control fails if an RDS instance is not deployed in a VPC.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.18"]}, "severity": "High", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

rds_instances = fugue.resources("aws_db_instance")

# Check if DB instance is in VPC by verifying either subnet group or security groups
is_in_vpc(db) {
	db.db_subnet_group_name != null
}

is_in_vpc(db) {
	count(db.vpc_security_group_ids) > 0
}

# Allow DB instances that are in a VPC
policy[p] {
	db := rds_instances[_]
	is_in_vpc(db)
	p = fugue.allow_resource(db)
}

# Deny DB instances that are not in a VPC
policy[p] {
	db := rds_instances[_]
	not is_in_vpc(db)
	p = fugue.deny_resource_with_message(db, "RDS instance must be deployed in a VPC for enhanced network security")
}
