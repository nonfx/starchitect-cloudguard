package rules.aws_aurora_security_groups

import data.fugue

__rego__metadoc__ := {
	"id": "2.2",
	"title": "Ensure the Use of Security Groups",
	"description": "Security groups act as a firewall for associated Amazon RDS DB instances, controlling both inbound and outbound traffic",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_2.2"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

aurora_clusters = fugue.resources("aws_rds_cluster")

security_groups = fugue.resources("aws_security_group")

aurora_has_security_group(cluster) {
	count(cluster.vpc_security_group_ids) > 0
}

security_group_has_inbound_rule(sg) {
	ingress_rule := sg.ingress[_]
	ingress_rule.from_port == ingress_rule.to_port
}

security_group_has_outbound_rule(sg) {
	count(sg.egress) > 0
}

policy[p] {
	cluster := aurora_clusters[_]
	aurora_has_security_group(cluster)
	sg_id := cluster.vpc_security_group_ids[_]
	sg := security_groups[sg_id]
	security_group_has_inbound_rule(sg)
	security_group_has_outbound_rule(sg)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := aurora_clusters[_]
	aurora_has_security_group(cluster)
	sg_id := cluster.vpc_security_group_ids[_]
	sg := security_groups[sg_id]
	security_group_has_inbound_rule(sg)
	security_group_has_outbound_rule(sg)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := aurora_clusters[_]
	not aurora_has_security_group(cluster)
	p = fugue.deny_resource_with_message(cluster, "Aurora cluster is not associated with any security group")
}

policy[p] {
	cluster := aurora_clusters[_]
	aurora_has_security_group(cluster)
	sg_id := cluster.vpc_security_group_ids[_]
	sg := security_groups[sg_id]
	not security_group_has_inbound_rule(sg)
	p = fugue.deny_resource_with_message(cluster, "Associated security group does not have proper inbound rules for Aurora")
}

policy[p] {
	cluster := aurora_clusters[_]
	aurora_has_security_group(cluster)
	sg_id := cluster.vpc_security_group_ids[_]
	sg := security_groups[sg_id]
	not security_group_has_outbound_rule(sg)
	p = fugue.deny_resource_with_message(cluster, "Associated security group does not have any outbound rules")
}
