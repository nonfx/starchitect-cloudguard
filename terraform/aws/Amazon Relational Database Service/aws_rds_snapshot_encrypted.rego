package rules.rds_snapshot_encrypted

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.4",
	"title": "RDS cluster snapshots and database snapshots should be encrypted at rest",
	"description": "This control checks if RDS DB snapshots and cluster snapshots are encrypted at rest. The control fails if snapshots are not encrypted.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all RDS snapshots and cluster snapshots
rds_snapshots = fugue.resources("aws_db_snapshot")

rds_cluster_snapshots = fugue.resources("aws_db_cluster_snapshot")

# Check if snapshot is encrypted
is_snapshot_encrypted(snapshot) {
	snapshot.encrypted == true
}

# Check if RDS DB cluster snapshot is encrypted
is_cluster_snapshot_encrypted(snapshot) {
	snapshot.storage_encrypted == true
}

# Policy for RDS DB snapshots
policy[p] {
	snapshot := rds_snapshots[_]
	is_snapshot_encrypted(snapshot)
	p = fugue.allow_resource(snapshot)
}

# Policy for RDS DB cluster snapshots
policy[p] {
	snapshot := rds_cluster_snapshots[_]
	is_cluster_snapshot_encrypted(snapshot)
	p = fugue.allow_resource(snapshot)
}

# Deny unencrypted RDS DB snapshots
policy[p] {
	snapshot := rds_snapshots[_]
	not is_snapshot_encrypted(snapshot)
	p = fugue.deny_resource_with_message(snapshot, "RDS DB snapshot must be encrypted at rest")
}

# Deny unencrypted RDS DB cluster snapshots
policy[p] {
	snapshot := rds_cluster_snapshots[_]
	not is_cluster_snapshot_encrypted(snapshot)
	p = fugue.deny_resource_with_message(snapshot, "RDS DB cluster snapshot must be encrypted at rest")
}
