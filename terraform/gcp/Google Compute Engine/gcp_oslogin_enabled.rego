package rules.gcp_oslogin_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "4.4",
	"title": "Ensure Oslogin Is Enabled for a Project",
	"description": "Enable OS login in GCP projects to bind SSH certificates with IAM users for centralized SSH key management. This helps in automated SSH key pair management and efficient handling of user access revocation.",
	"custom": {
		"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.4"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all compute project metadata resources
project_metadata = fugue.resources("google_compute_project_metadata")

# Get all compute instances
instances = fugue.resources("google_compute_instance")

# Helper to check if OS login is enabled in metadata
is_oslogin_enabled(metadata) {
	metadata.metadata["enable-oslogin"] == "true"
}

# Helper to check if OS login is enabled in instance metadata
is_instance_oslogin_enabled(instance) {
	instance.metadata["enable-oslogin"] == "true"
}

# Allow if project metadata has OS login enabled
policy[p] {
	metadata := project_metadata[_]
	is_oslogin_enabled(metadata)
	p = fugue.allow_resource(metadata)
}

# Deny if project metadata exists but OS login is not enabled
policy[p] {
	metadata := project_metadata[_]
	not is_oslogin_enabled(metadata)
	p = fugue.deny_resource_with_message(metadata, "OS login should be enabled at project level for centralized SSH key management")
}

# Check instances if project metadata doesn't exist
policy[p] {
	count(project_metadata) == 0
	instance := instances[_]
	is_instance_oslogin_enabled(instance)
	p = fugue.allow_resource(instance)
}

# Deny instances without OS login if project metadata doesn't exist
policy[p] {
	count(project_metadata) == 0
	instance := instances[_]
	not is_instance_oslogin_enabled(instance)
	p = fugue.deny_resource_with_message(instance, "OS login should be enabled either at project level or instance level")
}
