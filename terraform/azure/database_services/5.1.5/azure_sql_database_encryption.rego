package rules.azure_sql_database_encryption

import data.fugue

__rego__metadoc__ := {
    "id": "5.1.5",
    "title": "Ensure that 'Data encryption' is set to 'On' on a SQL Database",
    "description": "Enable Transparent Data Encryption on every SQL server to protect data at rest through real-time encryption and decryption.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.1.5"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all SQL databases
sql_databases = fugue.resources("azurerm_mssql_database")

# Helper to check if encryption is enabled
is_encrypted(database) {
    database.transparent_data_encryption_enabled == true
}

# Allow databases with encryption enabled
policy[p] {
    database := sql_databases[_]
    is_encrypted(database)
    p = fugue.allow_resource(database)
}

# Deny databases without encryption
policy[p] {
    database := sql_databases[_]
    not is_encrypted(database)
    p = fugue.deny_resource_with_message(database, "SQL Database must have transparent data encryption enabled")
}