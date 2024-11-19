package rules.neptune_cluster_snapshots_encrypted

import data.fugue

__rego__metadoc__ := {
	"id": "Neptune.6",
	"title": "Neptune DB cluster snapshots should be encrypted at rest",
	"description": "This control checks if Neptune DB cluster snapshots are encrypted at rest to protect data confidentiality and meet security compliance requirements.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Neptune.6"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

neptune_snapshots = fugue.resources("aws_neptune_cluster_snapshot")

# Helper function to check if snapshot is encrypted
is_encrypted(snapshot) {
	snapshot.storage_encrypted == true
}

policy[p] {
	snapshot := neptune_snapshots[_]
	is_encrypted(snapshot)
	p = fugue.allow_resource(snapshot)
}

policy[p] {
	snapshot := neptune_snapshots[_]
	not is_encrypted(snapshot)
	p = fugue.deny_resource_with_message(snapshot, "Neptune DB cluster snapshot must be encrypted at rest")
}
