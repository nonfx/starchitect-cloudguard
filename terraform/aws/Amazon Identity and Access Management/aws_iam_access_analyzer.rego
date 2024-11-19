package rules.aws_iam_access_analyzer

import data.fugue

__rego__metadoc__ := {
	"author": "rajat@nonfx.com",
	"id": "1.20",
	"title": "Ensure IAM Access Analyzer is enabled for all regions",
	"description": "Enable IAM Access Analyzer for IAM policies about all resources in each region. IAM Access Analyzer scans policies to show the accessible resources and helps in determining unintended user access.",
	"custom": {
		"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_1.20"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all IAM Role
iam_roles := fugue.resources("aws_iam_role")

# Check if IAM Access Analyzer is enabled
is_analyzer_enabled {
	# Get all IAM Access Analyzers
	analyzers = fugue.resources("aws_accessanalyzer_analyzer")
	analyzers[_].analyzer_name != null
}

# Policy rule that creates a set of judgements
policy[p] {
	is_analyzer_enabled
	p := fugue.allow_resource(iam_roles[_])
}

policy[p] {
	not is_analyzer_enabled
	p := fugue.deny_resource_with_message(iam_roles[_], "IAM Access Analyzer is not enabled for all the regions")
}
