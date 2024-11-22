package rules.aws_appsync_api_cache_encrypted

import data.fugue

__rego__metadoc__ := {
	"id": "AppSync.1",
	"title": "AWS AppSync API caches should be encrypted at rest",
	"description": "AWS AppSync API caches must implement encryption at rest to protect data confidentiality and prevent unauthorized access.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_AppSync.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

appsync_caches = fugue.resources("aws_appsync_api_cache")

# Helper function to check if cache encryption is enabled
is_cache_encrypted(cache) {
	cache.at_rest_encryption_enabled == true
}

# Allow if cache encryption is enabled
policy[p] {
	cache := appsync_caches[_]
	is_cache_encrypted(cache)
	p = fugue.allow_resource(cache)
}

# Deny if cache encryption is not enabled
policy[p] {
	cache := appsync_caches[_]
	not is_cache_encrypted(cache)
	p = fugue.deny_resource_with_message(cache, "AppSync API cache must be encrypted at rest")
}
