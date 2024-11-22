package rules.dms_redis_tls_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "DMS.12",
	"title": "DMS endpoints for Redis OSS should have TLS enabled",
	"description": "DMS endpoints for Redis OSS must have TLS enabled to ensure secure encrypted communication during data migration.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_DMS.12"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

dms_endpoints = fugue.resources("aws_dms_endpoint")

# Helper to check if endpoint is Redis and has TLS enabled
is_redis_tls_enabled(endpoint) {
	endpoint.engine_name == "redis"
	endpoint.ssl_mode == "verify-full"
}

# Helper to check if endpoint is Redis
is_redis_endpoint(endpoint) {
	endpoint.engine_name == "redis"
}

# Policy rule for allowing Redis endpoints with TLS enabled
policy[p] {
	endpoint := dms_endpoints[_]
	is_redis_endpoint(endpoint)
	is_redis_tls_enabled(endpoint)
	p = fugue.allow_resource(endpoint)
}

# Policy rule for denying Redis endpoints without TLS
policy[p] {
	endpoint := dms_endpoints[_]
	is_redis_endpoint(endpoint)
	not is_redis_tls_enabled(endpoint)
	p = fugue.deny_resource_with_message(
		endpoint,
		"DMS endpoint for Redis OSS must have TLS enabled for secure data migration",
	)
}

# Allow non-Redis endpoints
policy[p] {
	endpoint := dms_endpoints[_]
	not is_redis_endpoint(endpoint)
	p = fugue.allow_resource(endpoint)
}
