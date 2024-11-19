package rules.gcp_logging_sink_configured

import data.fugue

__rego__metadoc__ := {
	"id": "2.2",
	"title": "Ensure That Sinks Are Configured for All Log Entries",
	"description": "It is recommended to create a sink that will export copies of all the log entries. This can help aggregate logs from multiple projects and export them to a Security Information and Event Management (SIEM).",
	"custom": {
		"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.2"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all logging sinks
logging_sinks = fugue.resources("google_logging_project_sink")

# Helper to check if sink has valid destination
has_valid_destination(sink) {
	sink.destination != ""
}

# Allow if sink exists without filter and has valid destination
policy[p] {
	count(logging_sinks) > 0
	sink := logging_sinks[_]
	not sink.filter
	has_valid_destination(sink)
	p = fugue.allow_resource(sink)
}

# Deny if sink has filter
policy[p] {
	sink := logging_sinks[_]
	sink.filter
	p = fugue.deny_resource_with_message(sink, "Logging sink must not have a filter to ensure all log entries are exported")
}

# Deny if no sinks exist
policy[p] {
	count(logging_sinks) == 0
	p = fugue.missing_resource_with_message("google_logging_project_sink", "No logging sinks found - at least one sink must be configured to export all log entries")
}
