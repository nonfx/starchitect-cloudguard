package rules.aws_ebs_snapshot_block_public_access

import data.fugue

__rego__metadoc__ := {
	"id": "2.2.2",
	"title": "Ensure Public Access to EBS Snapshots is Disabled",
	"description": "To protect your data, ensure that public access to EBS snapshots is properly managed.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.2.2"]},
		"severity": "High",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

ebs_snapshot_public_access_blocked(snapshot_block_setting) {
	snapshot_block_setting.state == "block-all-sharing"
}

ebs_snapshot_public_access_blocked(snapshot_block_setting) {
	snapshot_block_setting.state == "block-new-sharing"
}

# Policy rule
policy[p] {
	snapshot_block_setting := fugue.resources("aws_ebs_snapshot_block_public_access")[_]
	ebs_snapshot_public_access_blocked(snapshot_block_setting)
	p = fugue.allow_resource(snapshot_block_setting)
}

policy[p] {
	snapshot_block_setting := fugue.resources("aws_ebs_snapshot_block_public_access")[_]
	not ebs_snapshot_public_access_blocked(snapshot_block_setting)
	p = fugue.deny_resource_with_message(snapshot_block_setting, "EBS Snapshot public access block setting is not configured to block public access.")
}

policy[p] {
	count(fugue.resources("aws_ebs_snapshot")) > 0
	count(fugue.resources("aws_ebs_snapshot_block_public_access")) == 0
	p = fugue.missing_resource_with_message("aws_ebs_snapshot_block_public_access", "EBS Snapshot public access block setting is missing while EBS snapshots exist.")
}
