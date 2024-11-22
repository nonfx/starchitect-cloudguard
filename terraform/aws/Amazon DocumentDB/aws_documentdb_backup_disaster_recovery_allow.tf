provider "aws" {
  region = "us-west-2"
}

resource "aws_docdb_cluster" "pass_example" {
  cluster_identifier      = "docdb-cluster-pass"
  engine                 = "docdb"
  master_username        = "docdbadmin"
  master_password        = "yourpassword"
  backup_retention_period = 7
  skip_final_snapshot    = false
  final_snapshot_identifier = "docdb-final-snapshot"
  deletion_protection    = true
  availability_zones     = ["us-west-2a", "us-west-2b", "us-west-2c"]
}
