package rules.azure_disk_encryption_cmk

import data.fugue

__rego__metadoc__ := {
    "id": "8.3",
    "title": "Ensure that 'OS and Data' disks are encrypted with Customer Managed Key",
    "description": "Ensure that OS disks (boot volumes) and data disks (non-boot volumes) are encrypted with CMK.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_8.3"]},"severity":"High","author":"Starchitect Agent"},
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

# Helper to check if disk encryption set uses CMK
is_valid_encryption_set(encryption_set) {
    encryption_set.key_vault_key_id != null
}

# Allow disks that are encrypted with CMK
policy[p] {
    disk := managed_disks[_]
    is_cmk_encrypted(disk)
    encryption_set := disk_encryption_sets[_]
    disk.disk_encryption_set_id == encryption_set.id
    is_valid_encryption_set(encryption_set)
    p = fugue.allow_resource(disk)
}

# Deny disks that are not encrypted with CMK
policy[p] {
    disk := managed_disks[_]
    not is_cmk_encrypted(disk)
    p = fugue.deny_resource_with_message(disk, "Managed disk must be encrypted with Customer Managed Key (CMK)")
}

# Deny disks with invalid encryption set
policy[p] {
    disk := managed_disks[_]
    is_cmk_encrypted(disk)
    encryption_set := disk_encryption_sets[_]
    disk.disk_encryption_set_id == encryption_set.id
    not is_valid_encryption_set(encryption_set)
    p = fugue.deny_resource_with_message(disk, "Disk encryption set must use a valid Customer Managed Key")
}