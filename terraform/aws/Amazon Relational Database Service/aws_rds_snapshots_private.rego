package rules.rds_snapshots_private

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.1",
	"title": "RDS snapshot should be private",
	"description": "RDS snapshots must be private and not publicly accessible to prevent unauthorized data exposure and maintain security compliance.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.1"]}, "severity": "Critical", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all RDS DB snapshots and cluster snapshots
db_snapshots = fugue.resources("aws_db_snapshot")

cluster_snapshots = fugue.resources("aws_db_cluster_snapshot")

# Helper to check if snapshot is private
is_private(snapshot) {
	not snapshot.shared_accounts
}

is_private(snapshot) {
	snapshot.shared_accounts == []
}

# Allow private DB snapshots
policy[p] {
	snapshot := db_snapshots[_]
	is_private(snapshot)
	p = fugue.allow_resource(snapshot)
}

# Deny public DB snapshots
policy[p] {
	snapshot := db_snapshots[_]
	not is_private(snapshot)
	p = fugue.deny_resource_with_message(snapshot, "RDS DB snapshot must not be publicly accessible")
}

# Allow private cluster snapshots
policy[p] {
	snapshot := cluster_snapshots[_]
	is_private(snapshot)
	p = fugue.allow_resource(snapshot)
}

# Deny public cluster snapshots
policy[p] {
	snapshot := cluster_snapshots[_]
	not is_private(snapshot)
	p = fugue.deny_resource_with_message(snapshot, "RDS cluster snapshot must not be publicly accessible")
}
