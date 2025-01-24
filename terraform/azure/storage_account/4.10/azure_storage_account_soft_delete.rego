package rules.storage_account_soft_delete

import data.fugue

__rego__metadoc__ := {
    "id": "4.10",
    "title": "Ensure Soft Delete is Enabled for Azure Containers and Blob Storage",
    "description": "Azure storage containers and blobs must have soft delete enabled to prevent data loss and enable recovery within retention period.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.10"]},"severity":"High"},
}

resource_type := "MULTIPLE"

storage_accounts = fugue.resources("azurerm_storage_account")

is_blob_soft_delete_enabled(account) {
    account.blob_properties[_].delete_retention_policy[_].days > 0
}

is_container_soft_delete_enabled(account) {
    account.blob_properties[_].container_delete_retention_policy[_].days > 0
}

policy[p] {
    account := storage_accounts[_]
    is_blob_soft_delete_enabled(account)
    is_container_soft_delete_enabled(account)
    p = fugue.allow_resource(account)
}

# Deny if blob soft delete is not enabled
policy[p] {
    account := storage_accounts[_]
    not is_blob_soft_delete_enabled(account)
    p = fugue.deny_resource_with_message(account, "Blob soft delete must be enabled with valid retention period")
}

# Deny if container soft delete is not enabled
policy[p] {
    account := storage_accounts[_]
    not is_container_soft_delete_enabled(account)
    p = fugue.deny_resource_with_message(account, "Container soft delete must be enabled with valid retention period")
}