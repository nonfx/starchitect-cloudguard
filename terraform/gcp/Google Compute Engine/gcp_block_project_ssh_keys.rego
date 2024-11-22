package rules.gcp_block_project_ssh_keys

import data.fugue

__rego__metadoc__ := {
	"id": "4.3",
	"title": "Ensure Block Project-Wide SSH Keys Is Enabled for VM Instances",
	"description": "Block project-wide SSH keys on VM instances to enhance security by preventing shared key access across all project instances.",
	"custom": {
		"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.3"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

# Get all GCP compute instances
instances = fugue.resources("google_compute_instance")

# Helper to check if project-wide SSH keys are blocked
is_project_ssh_keys_blocked(instance) {
	instance.metadata["block-project-ssh-keys"] == "true"
}

# Allow instances that block project-wide SSH keys
policy[p] {
	instance := instances[_]
	is_project_ssh_keys_blocked(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances that don't block project-wide SSH keys
policy[p] {
	instance := instances[_]
	not is_project_ssh_keys_blocked(instance)
	p = fugue.deny_resource_with_message(instance, "VM instance must have project-wide SSH keys blocked by setting metadata 'block-project-ssh-keys' to true")
}
