package rules.cloudtrail_multi_region_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "CloudTrail.1",
	"title": "CloudTrail should be enabled and configured with at least one multi-Region trail",
	"description": "CloudTrail must be enabled with multi-Region trail configuration capturing read/write management events for comprehensive AWS activity monitoring.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.1"]}, "severity": "High", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

cloudtrail_trails = fugue.resources("aws_cloudtrail")

# Helper function to check if trail is multi-region
is_multi_region(trail) {
	trail.is_multi_region_trail == true
}

# Helper function to check if management events are properly configured
has_management_events(trail) {
	event_selector := trail.event_selector[_]
	event_selector.include_management_events == true
	event_selector.read_write_type == "All"
}

# Helper function to check if trail is compliant
is_compliant(trail) {
	is_multi_region(trail)
	has_management_events(trail)
}

# Policy rule for existing trails
policy[p] {
	trail := cloudtrail_trails[_]
	is_compliant(trail)
	p = fugue.allow_resource(trail)
}

policy[p] {
	trail := cloudtrail_trails[_]
	not is_compliant(trail)
	p = fugue.deny_resource_with_message(trail, "CloudTrail must be configured as multi-region trail with both read and write management events enabled")
}

# Policy rule for when no trails exist
policy[p] {
	count(cloudtrail_trails) == 0
	p = fugue.missing_resource_with_message("aws_cloudtrail", "No CloudTrail trails are configured")
}
