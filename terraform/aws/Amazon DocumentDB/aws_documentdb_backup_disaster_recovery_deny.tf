provider "aws" {
  region = "us-west-2"
}

resource "aws_docdb_cluster" "fail_example" {
  cluster_identifier      = "docdb-cluster-fail"
  engine                 = "docdb"
  master_username        = "docdbadmin"
  master_password        = "yourpassword"
  backup_retention_period = 0
  skip_final_snapshot    = true
  deletion_protection    = false
  availability_zones     = ["us-west-2a"]
}
