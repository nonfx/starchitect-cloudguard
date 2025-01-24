package rules.azure_key_vault_logging

import data.fugue

__rego__metadoc__ := {
    "id": "6.1.4",
    "title": "Ensure that logging for Azure Key Vault is 'Enabled'",
    "description": "Enable AuditEvent logging for key vault instances to ensure interactions with key vaults are logged and available.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_6.1.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

key_vaults = fugue.resources("azurerm_key_vault")
diagnostic_settings = fugue.resources("azurerm_monitor_diagnostic_setting")

has_audit_logging(setting) {
    log := setting.log[_]
    log.category == "AuditEvent"
    log.enabled == true
}

is_vault_setting(setting, vault) {
    setting.target_resource_id == vault.id
}

policy[p] {
    vault := key_vaults[_]
    setting := diagnostic_settings[_]
    is_vault_setting(setting, vault)
    has_audit_logging(setting)
    p = fugue.allow_resource(vault)
}

policy[p] {
    vault := key_vaults[_]
    not vault_has_audit_logging(vault)
    p = fugue.deny_resource_with_message(vault, "Key Vault must have diagnostic settings enabled with AuditEvent logging")
}

vault_has_audit_logging(vault) {
    setting := diagnostic_settings[_]
    is_vault_setting(setting, vault)
    has_audit_logging(setting)
}