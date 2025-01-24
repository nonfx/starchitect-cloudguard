package rules.azure_unattached_disk_cmk_encryption

import data.fugue

__rego__metadoc__ := {
    "id": "8.4",
    "title": "Ensure Unattached Disks are Encrypted with CMK",
    "description": "Ensure that unattached disks in a subscription are encrypted with a Customer Managed Key (CMK).",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_8.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all managed disks
managed_disks = fugue.resources("azurerm_managed_disk")

# Get all disk encryption sets
disk_encryption_sets = fugue.resources("azurerm_disk_encryption_set")

# Helper to check if disk is encrypted with CMK
is_cmk_encrypted(disk) {
    disk.encryption_settings[_].enabled == true
    disk.disk_encryption_set_id != null
}

# Helper to check if disk is attached
is_attached(disk) {
    disk.managed_by != ""
}

# Allow if disk is attached or encrypted with CMK
policy[p] {
    disk := managed_disks[_]
    is_attached(disk)
    p = fugue.allow_resource(disk)
}

policy[p] {
    disk := managed_disks[_]
    not is_attached(disk)
    is_cmk_encrypted(disk)
    p = fugue.allow_resource(disk)
}

# Deny if disk is unattached and not encrypted with CMK
policy[p] {
    disk := managed_disks[_]
    not is_attached(disk)
    not is_cmk_encrypted(disk)
    p = fugue.deny_resource_with_message(disk, "Unattached managed disk must be encrypted with Customer Managed Key (CMK)")
}