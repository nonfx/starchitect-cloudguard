package rules.aws_memorydb_acl_configured

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "6.3",
	"title": "Ensure MemoryDB ACLs are properly configured",
	"description": "Ensure that Amazon MemoryDB clusters have ACLs properly configured to control access effectively, including user authentication and access strings.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_6.3"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

memorydb_clusters := fugue.resources("aws_memorydb_cluster")

memorydb_users := fugue.resources("aws_memorydb_user")

memorydb_acls := fugue.resources("aws_memorydb_acl")

acl_configured(cluster) {
	acl := memorydb_acls[_]
	cluster.acl_name == acl.id
}

user_configured(user) {
	user.access_string != null
	not contains(user.access_string, "all")
	user.authentication_mode[0].type == "password"
}

user_configured(user) {
	user.access_string != null
	not contains(user.access_string, "all")
	user.authentication_mode[0].type == "iam"
}

policy[p] {
	cluster := memorydb_clusters[_]
	acl_configured(cluster)
	user := memorydb_users[_]
	user_configured(user)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := memorydb_clusters[_]
	not acl_configured(cluster)
	p = fugue.deny_resource_with_message(cluster, "MemoryDB cluster does not have ACLs properly configured.")
}

policy[p] {
	cluster := memorydb_clusters[_]
	acl_configured(cluster)
	user := memorydb_users[_]
	not user_configured(user)
	p = fugue.deny_resource_with_message(cluster, "MemoryDB cluster does not have ACLs properly configured.")
}
