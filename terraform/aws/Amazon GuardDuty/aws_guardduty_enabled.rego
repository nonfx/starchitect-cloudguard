package rules.guardduty_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "GuardDuty.1",
	"title": "GuardDuty should be enabled",
	"description": "GuardDuty must be enabled across all AWS regions to detect unauthorized activity and monitor CloudTrail events for global services.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_GuardDuty.1"]}, "severity": "High"},
}

resource_type := "MULTIPLE"

# Get all GuardDuty detectors
detectors = fugue.resources("aws_guardduty_detector")

# Helper to check if detector is enabled
is_enabled(detector) {
	detector.enable == true
}

# Allow if detector exists and is enabled
policy[p] {
	count(detectors) > 0
	detector := detectors[_]
	is_enabled(detector)
	p = fugue.allow_resource(detector)
}

# Deny if detector exists but is disabled
policy[p] {
	count(detectors) > 0
	detector := detectors[_]
	not is_enabled(detector)
	p = fugue.deny_resource_with_message(detector, "GuardDuty detector must be enabled")
}

# Deny if no detector exists
policy[p] {
	count(detectors) == 0
	p = fugue.missing_resource_with_message("aws_guardduty_detector", "No GuardDuty detector found - GuardDuty must be enabled")
}
