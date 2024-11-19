provider "aws" {
  region = "us-west-2"
}

resource "aws_docdb_cluster" "fail_cluster" {
  cluster_identifier      = "docdb-cluster-fail"
  engine                 = "docdb"
  master_username        = "docMaster"
  master_password        = "must-be-16-characters"
  skip_final_snapshot    = true
}
