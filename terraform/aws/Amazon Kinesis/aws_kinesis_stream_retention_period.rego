package rules.kinesis_stream_retention_period

# Import the fugue library for resource evaluation
import data.fugue

# Metadata for the rule including ID, title, and description
__rego__metadoc__ := {
	"id": "Kinesis.3",
	"title": "Kinesis streams should have an adequate data retention period",
	"description": "This control checks if Kinesis data streams retain data for at least 168 hours (7 days). Adequate retention periods ensure data preservation and accessibility.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Kinesis.3"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

# Specify that this rule applies to multiple resource types
resource_type := "MULTIPLE"

# Get all Kinesis stream resources
kinesis_streams = fugue.resources("aws_kinesis_stream")

# Define minimum retention period (7 days in hours)
min_retention_period = 168

# Helper function to validate retention period
has_adequate_retention(stream) {
	stream.retention_period >= min_retention_period
}

# Allow resources that meet the retention period requirement
policy[p] {
	stream := kinesis_streams[_]
	has_adequate_retention(stream)
	p = fugue.allow_resource(stream)
}

# Deny resources that don't meet the retention period requirement
policy[p] {
	stream := kinesis_streams[_]
	not has_adequate_retention(stream)
	p = fugue.deny_resource_with_message(stream, sprintf("Kinesis stream retention period must be at least %d hours", [min_retention_period]))
}
