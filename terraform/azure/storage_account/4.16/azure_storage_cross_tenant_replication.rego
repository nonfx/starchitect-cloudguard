package rules.storage_cross_tenant_replication

import data.fugue

__rego__metadoc__ := {
    "id": "4.16",
    "title": "Ensure 'Cross Tenant Replication' is not enabled",
    "description": "Azure storage accounts must disable cross-tenant replication to prevent unauthorized data sharing across different tenant boundaries.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.16"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage accounts
storage_accounts = fugue.resources("azurerm_storage_account")

# Helper to check if cross-tenant replication is disabled
is_cross_tenant_disabled(account) {
    account.allow_cross_tenant_replication == false
}

# Allow if cross-tenant replication is disabled
policy[p] {
    account := storage_accounts[_]
    is_cross_tenant_disabled(account)
    p = fugue.allow_resource(account)
}

# Deny if cross-tenant replication is enabled or not explicitly disabled
policy[p] {
    account := storage_accounts[_]
    not is_cross_tenant_disabled(account)
    p = fugue.deny_resource_with_message(account, "Storage account must have cross-tenant replication disabled to prevent unauthorized data sharing")
}