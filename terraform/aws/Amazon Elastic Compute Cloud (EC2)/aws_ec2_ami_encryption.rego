package rules.aws_ec2_ami_encryption

import data.fugue

__rego__metadoc__ := {
	"id": "2.1.2",
	"title": "Ensure Images (AMI's) are encrypted",
	"description": "Amazon Machine Images should utilize EBS Encrypted snapshots.",
	"custom": {"controls":{"CIS-AWS-Compute-Services-Benchmark_v1.0.0":["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.1.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

amis := fugue.resources("aws_ami")

# Check if all block devices for the AMI are encrypted
block_device_encrypted(ami) {
	ebs_block_device := ami.ebs_block_device[_]
	ebs_block_device.encrypted == true
}

policy[p] {
	ami := amis[_]
	block_device_encrypted(ami)
	p := fugue.allow_resource(ami)
}

policy[p] {
	ami := amis[_]
	not block_device_encrypted(ami)
	p := fugue.deny_resource(ami)
}
