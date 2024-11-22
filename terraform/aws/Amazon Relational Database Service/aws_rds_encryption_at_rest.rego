# Package declaration for the rule
package rules.rds_encryption_at_rest

# Import the fugue library
import data.fugue

__rego__metadoc__ := {
	"id": "2.3.1",
	"title": "Ensure that encryption-at-rest is enabled for RDS Instances",
	"description": "Amazon RDS encrypted DB instances use the industry standard AES-256 encryption algorithm to encrypt your data on the server that hosts your Amazon RDS DB instances. After your data is encrypted, Amazon RDS handles authentication of access and decryption of your data transparently with a minimal impact on performance.",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_2.3.1"], "CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_3.5"]}, "severity": "Low", "author": "Starchitect Agent"},
}

# Set resource type to MULTIPLE for advanced rule
resource_type := "MULTIPLE"

# Query for all RDS instances
rds_instances = fugue.resources("aws_db_instance")

# Auxiliary function to check if an RDS instance is encrypted
is_encrypted(resource) {
	resource.storage_encrypted == true
}

# Policy rule that holds the set of judgements
policy[p] {
	resource = rds_instances[_]
	is_encrypted(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = rds_instances[_]
	not is_encrypted(resource)
	p = fugue.deny_resource_with_message(resource, "RDS instance must have encryption-at-rest enabled")
}
