package rules.gcp_access_approval_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "2.15",
	"title": "Ensure 'Access Approval' is 'Enabled'",
	"description": "GCP Access Approval enables you to require your organizations' explicit approval whenever Google support try to access your projects. This adds an additional control and logging of who in your organization approved/denied these requests.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.15"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all access approval settings
approval_settings = fugue.resources("google_project_access_approval_settings")

# Helper function to check if access approval is properly configured
is_properly_configured(setting) {
	setting.enrolled_services[_].cloud_product == "all"
	setting.enrolled_services[_].enrollment_level == "BLOCK_ALL"
	count(setting.notification_emails) > 0
}

# Allow if access approval is properly configured
policy[p] {
	setting := approval_settings[_]
	is_properly_configured(setting)
	p = fugue.allow_resource(setting)
}

# Deny if access approval settings are missing or improperly configured
policy[p] {
	setting := approval_settings[_]
	not is_properly_configured(setting)
	p = fugue.deny_resource_with_message(setting, "Access Approval must be enabled with proper configuration: enrolled_services set to 'all' with BLOCK_ALL enrollment level and notification_emails configured")
}
