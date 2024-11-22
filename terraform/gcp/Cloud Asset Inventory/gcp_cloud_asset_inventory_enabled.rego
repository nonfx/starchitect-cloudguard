package rules.gcp_cloud_asset_inventory_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "2.13",
	"title": "Ensure Cloud Asset Inventory Is Enabled",
	"description": "GCP Cloud Asset Inventory provides historical view of GCP resources and IAM policies through a time-series database. The service should be enabled for security tracking and compliance auditing.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.13"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all project services
project_services = fugue.resources("google_project_service")

# Helper function to check if Cloud Asset Inventory API is enabled and properly configured
is_cloud_asset_enabled(service) {
	service.service == "cloudasset.googleapis.com"
	not service.disable_dependent_services
	not service.disable_on_destroy
}

# Allow if Cloud Asset Inventory API is properly configured
policy[p] {
	service := project_services[_]
	is_cloud_asset_enabled(service)
	p = fugue.allow_resource(service)
}

# Deny if Cloud Asset Inventory API is not properly configured
policy[p] {
	service := project_services[_]
	service.service == "cloudasset.googleapis.com"
	not is_cloud_asset_enabled(service)
	p = fugue.deny_resource_with_message(service, "Cloud Asset Inventory API must be properly configured with disable_dependent_services and disable_on_destroy set to false")
}
