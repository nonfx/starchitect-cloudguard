package rules.rds_non_default_ports

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.23",
	"title": "RDS instances should not use a database engine default port",
	"description": "RDS instances must use non-default database engine ports to enhance security by avoiding predictable port configurations.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.23"]}, "severity": "Low", "author": "llmagent"},
}

resource_type := "MULTIPLE"

# Query for all db instances
aws_db_instance = fugue.resources("aws_db_instance")

# Define default ports for different database engines
default_ports = {
	"mysql": 3306,
	"postgres": 5432,
	"oracle-ee": 1521,
	"oracle-se2": 1521,
	"oracle-se1": 1521,
	"oracle-se": 1521,
	"sqlserver-ee": 1433,
	"sqlserver-se": 1433,
	"sqlserver-ex": 1433,
	"sqlserver-web": 1433,
	"mariadb": 3306,
}

# Check if instance uses default port
uses_default_port(db) {
	db.port == default_ports[db.engine]
}

# Allow instances that don't use default ports
policy[p] {
	db := aws_db_instance[_]
	not uses_default_port(db)
	p = fugue.allow_resource(db)
}

# Deny instances using default ports
policy[p] {
	db := aws_db_instance[_]
	uses_default_port(db)
	p = fugue.deny_resource_with_message(
		db,
		sprintf(
			"RDS instance uses default port %d for engine %s. Use a non-default port to enhance security.",
			[db.port, db.engine],
		),
	)
}
