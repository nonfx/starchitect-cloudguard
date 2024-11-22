provider "aws" {
  region = "us-west-2"
}

resource "aws_rds_cluster_parameter_group" "aurora_params_pass" {
  family = "aurora-postgresql12"
  name   = "aurora-cluster-demo-params-pass"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_rds_cluster" "aurora_cluster_pass" {
  cluster_identifier      = "aurora-cluster-demo-pass"
  engine                  = "aurora-postgresql"
  engine_version          = "5.7.mysql_aurora.2.03.2"
  availability_zones      = ["us-west-2a", "us-west-2b"]
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "bar"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"

  # Using parameter group that enforces SSL
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.aurora_params_pass.name
}
