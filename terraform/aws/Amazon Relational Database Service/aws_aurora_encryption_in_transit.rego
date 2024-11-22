package rules.aws_aurora_encryption_in_transit

import data.fugue

__rego__metadoc__ := {
	"id": "2.4",
	"title": "Ensure Data in Transit is Encrypted",
	"description": "Use SSL (Secure Sockets Layer) to secure data in transit. Aurora supports SSL-encrypted connections between your application and your DB instance",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_2.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

aurora_clusters = fugue.resources("aws_rds_cluster")

aurora_cluster_parameters = fugue.resources("aws_rds_cluster_parameter_group")

aurora_ssl_enforced(cluster) {
	parameter_group_name := cluster.db_cluster_parameter_group_name
	parameter_group := aurora_cluster_parameters[_]
	parameter_group.name == parameter_group_name
	startswith(aurora_cluster_parameters[_].family, "aurora-postgresql")
	param := parameter_group.parameter[_]
	param.name == "rds.force_ssl"
	param.value == "1"
}

aurora_ssl_enforced(cluster) {
	parameter_group_name := cluster.db_cluster_parameter_group_name
	parameter_group := aurora_cluster_parameters[_]
	parameter_group.name == parameter_group_name
	startswith(aurora_cluster_parameters[_].family, "aurora-mysql")
	param := parameter_group.parameter[_]
	param.name == "require_secure_transport"
	param.value == "1"
}

policy[p] {
	cluster := aurora_clusters[_]
	aurora_ssl_enforced(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := aurora_clusters[_]
	not aurora_ssl_enforced(cluster)
	debug_msg := "Aurora cluster does not enforce SSL connections"
	p = fugue.deny_resource_with_message(cluster, debug_msg)
}
