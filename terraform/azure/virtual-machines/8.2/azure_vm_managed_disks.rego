package rules.azure_vm_managed_disks

import data.fugue

__rego__metadoc__ := {
    "id": "8.2",
    "title": "Ensure Virtual Machines are utilizing Managed Disks",
    "description": "Migrate blob-based VHDs to Managed Disks on Virtual Machines to exploit the default features of this configuration.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_8.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Virtual Machines
virtual_machines = fugue.resources("azurerm_virtual_machine")

# Helper to check if VM uses managed disks
is_using_managed_disks(vm) {
    vm.storage_os_disk[_].managed_disk_type != ""
}

is_using_managed_disks(vm) {
    vm.storage_data_disk[_].managed_disk_type != ""
}

# Allow VMs that use managed disks
policy[p] {
    vm := virtual_machines[_]
    is_using_managed_disks(vm)
    p = fugue.allow_resource(vm)
}

# Deny VMs that don't use managed disks
policy[p] {
    vm := virtual_machines[_]
    not is_using_managed_disks(vm)
    p = fugue.deny_resource_with_message(vm, "Virtual Machine must use managed disks instead of blob-based VHDs for enhanced security and reliability")
}