package rules.gcp_api_key_restrictions

import data.fugue

__rego__metadoc__ := {
	"id": "1.14",
	"title": "Ensure API Keys Are Restricted to Only APIs That Application Needs Access",
	"description": "API Keys should only be used for services in cases where other authentication methods are unavailable. API keys are always at risk because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides.",
	"custom": {
		"controls": {"CIS_Google_Cloud_Platform_Foundation_Benchmark_v3.0.0": ["CIS_Google_Cloud_Platform_Foundation_Benchmark_v3.0.0_1.14"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

# Get all API key resources
api_keys = fugue.resources("google_apikeys_key")

# Helper to check if API restrictions are configured
has_api_restrictions(key) {
	count(key.restrictions) > 0
	count(key.restrictions[_].api_targets) > 0
}

# Allow if API restrictions are configured
policy[p] {
	key := api_keys[_]
	has_api_restrictions(key)
	p = fugue.allow_resource(key)
}

# Deny if API restrictions are not configured
policy[p] {
	key := api_keys[_]
	not has_api_restrictions(key)
	p = fugue.deny_resource_with_message(key, "API key must have API target restrictions configured to limit access to only required APIs")
}
