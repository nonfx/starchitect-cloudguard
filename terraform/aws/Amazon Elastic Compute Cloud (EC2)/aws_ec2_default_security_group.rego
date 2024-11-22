package rules.aws_ec2_default_security_group

import data.fugue

__rego__metadoc__ := {
	"id": "2.7",
	"title": "Ensure Default EC2 Security groups are not being used",
	"description": "When an EC2 instance is launched a specified custom security group should be assigned to the instance",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.7"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

ec2_instances := fugue.resources("aws_instance")

security_groups := fugue.resources("aws_security_group")

is_default_security_group(sg) {
	sg.name == "default"
}

instance_uses_default_sg(instance) {
	sg_id := instance.vpc_security_group_ids[_]
	sg := security_groups[sg_id]
	is_default_security_group(sg)
}

policy[p] {
	instance := ec2_instances[_]
	not instance_uses_default_sg(instance)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := ec2_instances[_]
	instance_uses_default_sg(instance)
	msg := sprintf("EC2 instance '%s' is using the default security group. Assign a custom security group instead.", [instance.id])
	p = fugue.deny_resource_with_message(instance, msg)
}

policy[p] {
	sg := security_groups[_]
	is_default_security_group(sg)
	count(sg.ingress) == 0
	count(sg.egress) == 0
	p = fugue.allow_resource(sg)
}

policy[p] {
	sg := security_groups[_]
	is_default_security_group(sg)
	count(sg.ingress) > 0
	msg := sprintf("Default security group '%s' has inbound rules. Remove all inbound rules from the default security group.", [sg.id])
	p = fugue.deny_resource_with_message(sg, msg)
}

policy[p] {
	sg := security_groups[_]
	is_default_security_group(sg)
	count(sg.egress) > 0
	msg := sprintf("Default security group '%s' has outbound rules. Remove all outbound rules from the default security group.", [sg.id])
	p = fugue.deny_resource_with_message(sg, msg)
}
