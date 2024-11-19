provider "aws" {
  region = "us-west-2"
}

resource "aws_kms_key" "aurora_encryption_key" {
  description             = "KMS key for Aurora cluster encryption"
  deletion_window_in_days = 10
}

resource "aws_rds_cluster" "aurora_cluster_pass" {
  cluster_identifier      = "aurora-cluster-demo"
  engine                  = "aurora-mysql"
  engine_version          = "5.7.mysql_aurora.2.03.2"
  availability_zones      = ["us-west-2a", "us-west-2b"]
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "bar"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"

  # Encryption at rest is enabled
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.aurora_encryption_key.arn
}
