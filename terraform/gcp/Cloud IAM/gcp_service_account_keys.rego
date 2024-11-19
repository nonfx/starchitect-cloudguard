package rules.gcp_service_account_keys

import data.fugue

__rego__metadoc__ := {
	"id": "1.4",
	"title": "Ensure That There Are Only GCP-Managed Service Account Keys",
	"description": "Service accounts should only use GCP-managed keys and avoid user-managed service account keys to reduce security risks.",
	"custom": {
		"controls": {"CIS_Google_Cloud_Platform_Foundation_Benchmark_v3.0.0": ["CIS_Google_Cloud_Platform_Foundation_Benchmark_v3.0.0_1.4"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

# Get all resources
service_accounts = fugue.resources("google_service_account")

service_account_keys = fugue.resources("google_service_account_key")

# Helper to check if key is user-managed
is_user_managed_key(key) {
	key.private_key_type == "TYPE_GOOGLE_CREDENTIALS_FILE"
}

# Allow service accounts that don't have user-managed keys
policy[p] {
	sa := service_accounts[_]
	count([key | key := service_account_keys[_]; is_user_managed_key(key)]) == 0
	p = fugue.allow_resource(sa)
}

# Deny service accounts that have user-managed keys
policy[p] {
	key := service_account_keys[_]
	is_user_managed_key(key)
	p = fugue.deny_resource_with_message(key, "User-managed service account keys are not allowed. Use GCP-managed keys instead.")
}
