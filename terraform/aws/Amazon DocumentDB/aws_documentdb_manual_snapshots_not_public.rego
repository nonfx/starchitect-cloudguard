package rules.documentdb_manual_snapshots_not_public

import data.fugue

__rego__metadoc__ := {
	"id": "DocumentDB.3",
	"title": "Amazon DocumentDB manual cluster snapshots should not be public",
	"description": "This control checks if DocumentDB manual cluster snapshots are public. Public snapshots can expose sensitive data to unauthorized users and should be restricted.",
	"custom": {"severity":"Critical","controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_DocumentDB.3"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all DocumentDB cluster snapshots
db_snapshots = fugue.resources("aws_db_cluster_snapshot")

# Helper to check if snapshot is public
is_public(snapshot) {
	snapshot.shared_accounts[_] == "all"
}

# Allow if snapshot is not public
policy[p] {
	snapshot := db_snapshots[_]
	not is_public(snapshot)
	p = fugue.allow_resource(snapshot)
}

# Deny if snapshot is public
policy[p] {
	snapshot := db_snapshots[_]
	is_public(snapshot)
	p = fugue.deny_resource_with_message(snapshot, "DocumentDB cluster snapshot should not be public. Remove public access to prevent unauthorized access.")
}
