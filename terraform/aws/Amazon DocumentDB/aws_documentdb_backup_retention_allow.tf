provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_docdb_cluster" "pass_test" {
  provider = aws.pass_aws
  cluster_identifier = "pass-docdb-cluster"
  engine             = "docdb"
  master_username    = "foo"
  master_password    = "mustbeeightchars"
  backup_retention_period = 7  # Meets minimum requirement of 7 days

  skip_final_snapshot = true
}
