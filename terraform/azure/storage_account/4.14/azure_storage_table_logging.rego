package rules.storage_table_logging

import data.fugue

__rego__metadoc__ := {
    "id": "4.14",
    "title": "Ensure Storage Logging is Enabled for Table Service for Read, Write, and Delete Requests",
    "description": "Azure Table storage requires server-side logging enabled for read, write, and delete operations to monitor request details.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.14"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

storage_accounts = fugue.resources("azurerm_storage_account")
diagnostic_settings = fugue.resources("azurerm_monitor_diagnostic_setting")

is_log_category_enabled(setting, category) {
    log := setting.enabled_log[_]
    log.category == category
}

has_table_logging(account) {
    setting := diagnostic_settings[_]
    setting.target_resource_id == account.id
    is_log_category_enabled(setting, "StorageRead")
    is_log_category_enabled(setting, "StorageWrite")
    is_log_category_enabled(setting, "StorageDelete")
}

policy[p] {
    account := storage_accounts[_]
    has_table_logging(account)
    p = fugue.allow_resource(account)
}

policy[p] {
    account := storage_accounts[_]
    not has_table_logging(account)
    p = fugue.deny_resource_with_message(account, "Storage account must have table service logging enabled for read, write, and delete operations")
}