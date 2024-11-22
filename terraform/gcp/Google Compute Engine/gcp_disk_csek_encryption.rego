package rules.gcp_disk_csek_encryption

import data.fugue

__rego__metadoc__ := {
	"id": "4.7",
	"title": "Ensure VM Disks for Critical VMs Are Encrypted With Customer-Supplied Encryption Key (CSEK)",
	"description": "Customer-Supplied Encryption Keys (CSEK) are required for critical VM disks to ensure enhanced data protection and control over encryption keys.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_4.7"]}, "severity": "High", "author": "Starchitect Agent"},
}

# Define resource type as MULTIPLE since we're checking multiple disk resources
resource_type := "MULTIPLE"

# Get all compute disks
disks = fugue.resources("google_compute_disk")

# Helper function to check if disk uses CSEK
has_csek_encryption(disk) {
	disk.disk_encryption_key[_] != null
}

# Allow rule for disks that use CSEK
policy[p] {
	disk := disks[_]
	has_csek_encryption(disk)
	p = fugue.allow_resource(disk)
}

# Deny rule for disks that don't use CSEK
policy[p] {
	disk := disks[_]
	not has_csek_encryption(disk)
	p = fugue.deny_resource_with_message(
		disk,
		sprintf("Disk %v must be encrypted with Customer-Supplied Encryption Keys (CSEK) for enhanced security", [disk.name]),
	)
}
