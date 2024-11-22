provider "aws" {
  region = "us-west-2"
}

resource "aws_rds_cluster" "passing_cluster" {
  cluster_identifier      = "passing-aurora-cluster"
  engine                  = "aurora-mysql"
  engine_version          = "5.7.mysql_aurora.2.03.2"
  availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "bar"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.example.arn
}

resource "aws_kms_key" "example" {
  description             = "Example KMS Key"
  deletion_window_in_days = 10
}
