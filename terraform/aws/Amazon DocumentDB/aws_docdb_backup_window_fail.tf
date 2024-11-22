provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_docdb_cluster" "passing_example" {
  provider              = aws.passing
  cluster_identifier    = "passing-docdb-cluster"
  engine                = "docdb"
  master_username       = "username"
  master_password       = "password"
  backup_retention_period = 5
  # preferred_backup_window = "07:00-09:00"
  skip_final_snapshot   = true
}
