package rules.aws_ami_private

import data.fugue

__rego__metadoc__ := {
	"id": "2.1.5",
	"title": "Ensure Images are not Publicly Available",
	"description": "EC2 allows you to make an AMI public, sharing it with all AWS accounts",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.1.5"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

amis := fugue.resources("aws_ami")

launch_permissions := fugue.resources("aws_ami_launch_permission")

# Check if any AMI is public
public_amis := {ami |
	ami := amis[_]
	public_permission := launch_permissions[_]
	public_permission.image_id == ami.id
	public_permission.group == "all"
}

policy[p] {
	ami := amis[_]
	not ami_public(ami)
	p := fugue.allow_resource(ami)
}

policy[p] {
	ami := amis[_]
	ami_public(ami)
	p := fugue.deny_resource(ami)
}

# Check if an AMI is public based on launch permissions
ami_public(ami) {
	public_permission := launch_permissions[_]
	public_permission.image_id == ami.id
	public_permission.group == "all"
}
