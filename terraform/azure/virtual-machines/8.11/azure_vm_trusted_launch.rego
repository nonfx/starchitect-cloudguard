package rules.azure_vm_trusted_launch

import data.fugue

__rego__metadoc__ := {
    "id": "8.11",
    "title": "Ensure Trusted Launch is enabled on Virtual Machines",
    "description": "When Secure Boot and vTPM are enabled together, they provide a strong foundation for protecting your VM from boot attacks.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_8.11"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Virtual Machines (both Windows and Linux)
windows_vms = fugue.resources("azurerm_windows_virtual_machine")
linux_vms = fugue.resources("azurerm_linux_virtual_machine")

# Helper to check if Trusted Launch is properly configured
is_trusted_launch_enabled(vm) {
    vm.secure_boot_enabled == true
    vm.vtpm_enabled == true
}

# Allow if VM has Trusted Launch enabled
policy[p] {
    vm := windows_vms[_]
    is_trusted_launch_enabled(vm)
    p = fugue.allow_resource(vm)
}

policy[p] {
    vm := linux_vms[_]
    is_trusted_launch_enabled(vm)
    p = fugue.allow_resource(vm)
}

# Deny if VM does not have Trusted Launch enabled
policy[p] {
    vm := windows_vms[_]
    not is_trusted_launch_enabled(vm)
    p = fugue.deny_resource_with_message(vm, "Virtual Machine must have Trusted Launch enabled with both Secure Boot and vTPM for enhanced security against boot-level attacks")
}

policy[p] {
    vm := linux_vms[_]
    not is_trusted_launch_enabled(vm)
    p = fugue.deny_resource_with_message(vm, "Virtual Machine must have Trusted Launch enabled with both Secure Boot and vTPM for enhanced security against boot-level attacks")
}