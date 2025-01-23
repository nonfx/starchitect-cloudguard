package rules.azure_sql_tde_cmk

import data.fugue

__rego__metadoc__ := {
    "id": "5.1.3",
    "title": "Ensure SQL server's TDE protector is encrypted with Customer-managed key",
    "description": "Transparent Data Encryption (TDE) with Customer-managed key support provides increased transparency and control over the TDE Protector, enhancing security through Azure Key Vault integration.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.1.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

sql_servers[id] = server {
    server := fugue.resources("azurerm_mssql_server")[id]
}

encryption_protectors[id] = protector {
    protector := fugue.resources("azurerm_mssql_server_transparent_data_encryption")[id]
}

is_customer_managed(protector) {
    protector.key_vault_key_id != null
}

policy[p] {
    server := sql_servers[server_id]
    protector := encryption_protectors[protector_id]
    protector.server_id == server.id
    is_customer_managed(protector)
    p = fugue.allow_resource(server)
}

policy[p] {
    server := sql_servers[server_id]
    protector := encryption_protectors[protector_id]
    protector.server_id == server.id
    not is_customer_managed(protector)
    p = fugue.deny_resource_with_message(server, "SQL Server must use customer-managed key for TDE protector encryption")
}

policy[p] {
    server := sql_servers[server_id]
    not any_matching_protector(server.id)
    p = fugue.deny_resource_with_message(server, "SQL Server must have TDE protector configured with customer-managed key")
}

any_matching_protector(server_id) {
    encryption_protectors[_].server_id == server_id
}