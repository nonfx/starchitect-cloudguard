provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_docdb_cluster" "fail_test" {
  provider = aws.fail_aws
  cluster_identifier = "fail-docdb-cluster"
  engine             = "docdb"
  master_username    = "foo"
  master_password    = "mustbeeightchars"
  backup_retention_period = 5  # Less than required 7 days

  skip_final_snapshot = true
}
