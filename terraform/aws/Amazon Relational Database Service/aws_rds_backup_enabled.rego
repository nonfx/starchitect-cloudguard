package rules.aws_rds_backup_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "3.10",
	"title": "Ensure to Enable Backup and Recovery",
	"description": "This rule checks if RDS instances have automated backups enabled with a retention period greater than 0 days.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_3.10"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

aws_db_instances = fugue.resources("aws_db_instance")

backup_enabled(resource) {
	resource.backup_retention_period > 0
}

policy[p] {
	aws_db_instance := aws_db_instances[_]
	backup_enabled(aws_db_instance)
	p = fugue.allow_resource(aws_db_instance)
}

policy[p] {
	aws_db_instance := aws_db_instances[_]
	not backup_enabled(aws_db_instance)
	msg := sprintf("RDS instance %s does not have automated backups enabled or has a retention period of 0 days.", [aws_db_instance.id])
	p = fugue.deny_resource_with_message(aws_db_instance, msg)
}
