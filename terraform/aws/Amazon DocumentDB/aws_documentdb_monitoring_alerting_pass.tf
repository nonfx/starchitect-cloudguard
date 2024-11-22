provider "aws" {
  region = "us-west-2"
}

resource "aws_docdb_cluster" "pass_cluster" {
  cluster_identifier      = "docdb-cluster-pass"
  engine                 = "docdb"
  master_username        = "docMaster"
  master_password        = "must-be-16-characters"
  skip_final_snapshot    = true

  enabled_cloudwatch_logs_exports = ["audit"]
}
