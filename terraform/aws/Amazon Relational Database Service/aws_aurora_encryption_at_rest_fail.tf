provider "aws" {
  region = "us-west-2"
}

resource "aws_rds_cluster" "failing_cluster" {
  cluster_identifier      = "failing-aurora-cluster"
  engine                  = "aurora-mysql"
  engine_version          = "5.7.mysql_aurora.2.03.2"
  availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "bar"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  storage_encrypted       = false
}
