package rules.azure_storage_logging

import data.fugue

__rego__metadoc__ := {
    "id": "STORAGE_LOGGING",
    "title": "Ensure Storage logging is Enabled for Blob Service for Read, Write, and Delete requests",
    "description": "Storage accounts should have logging enabled for all blob operations to maintain audit trail and security monitoring.",
    "custom": {
        "severity": "Medium",
        "controls": {
            "CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0": [
                "CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.13"
            ]
        }
    }
}

resource_type := "MULTIPLE"

storage_accounts = fugue.resources("azurerm_storage_account")

is_logging_enabled(account) {
    blob_props := account.blob_properties[_]
    blob_props.change_feed_enabled == true
    blob_props.versioning_enabled == true
    blob_props.last_access_time_enabled == true

    delete_policy := blob_props.delete_retention_policy[_]
    delete_policy.days > 0

    container_policy := blob_props.container_delete_retention_policy[_]
    container_policy.days > 0
}

policy[p] {
    account := storage_accounts[_]
    is_logging_enabled(account)
    p = fugue.allow_resource(account)
}

policy[p] {
    account := storage_accounts[_]
    not is_logging_enabled(account)
    p = fugue.deny_resource_with_message(
        account,
        "Storage account must enable logging features: change feed, versioning, last access time tracking, and retention policies"
    )
}