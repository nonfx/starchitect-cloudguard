package rules.rds_instance_custom_admin_username

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.25",
	"title": "RDS database instances should use a custom administrator username",
	"description": "RDS database instances must use custom administrator usernames instead of default values to enhance security and prevent unauthorized access.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.25"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Query for all db instances
aws_db_instance = fugue.resources("aws_db_instance")

# Check if instance uses default admin username
policy[p] {
	db := aws_db_instance[_]
	db.username != "admin"
	db.username != "postgres"
	db.username != "root"
	p = fugue.allow_resource(db)
}

policy[p] {
	db := aws_db_instance[_]
	db.username == "admin"
	p = fugue.deny_resource_with_message(db, "RDS instance uses default admin username 'admin'. Use a custom administrator username.")
}

policy[p] {
	db := aws_db_instance[_]
	db.username == "postgres"
	p = fugue.deny_resource_with_message(db, "RDS instance uses default admin username 'postgres'. Use a custom administrator username.")
}

policy[p] {
	db := aws_db_instance[_]
	db.username == "root"
	p = fugue.deny_resource_with_message(db, "RDS instance uses default admin username 'root'. Use a custom administrator username.")
}
