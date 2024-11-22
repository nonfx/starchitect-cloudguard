package rules.documentdb_backup_retention

import data.fugue

__rego__metadoc__ := {
	"id": "DocumentDB.2",
	"title": "Amazon DocumentDB clusters should have an adequate backup retention period",
	"description": "Amazon DocumentDB clusters must maintain backup retention periods of at least 7 days to ensure data recovery capabilities.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_DocumentDB.2"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

docdb_clusters = fugue.resources("aws_docdb_cluster")

# Minimum required backup retention period in days
MIN_BACKUP_RETENTION_DAYS = 7

# Helper to check if backup retention period is adequate
has_adequate_backup_retention(cluster) {
	cluster.backup_retention_period >= MIN_BACKUP_RETENTION_DAYS
}

# Policy rule for allowing clusters with adequate backup retention
policy[p] {
	cluster := docdb_clusters[_]
	has_adequate_backup_retention(cluster)
	p = fugue.allow_resource(cluster)
}

# Policy rule for denying clusters with inadequate backup retention
policy[p] {
	cluster := docdb_clusters[_]
	not has_adequate_backup_retention(cluster)
	p = fugue.deny_resource_with_message(
		cluster,
		sprintf("DocumentDB cluster backup retention period must be at least %d days", [MIN_BACKUP_RETENTION_DAYS]),
	)
}
