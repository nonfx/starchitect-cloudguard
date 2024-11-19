provider "aws" {
  region = "us-west-2"
}

resource "aws_neptune_cluster" "passing_cluster" {
  cluster_identifier                  = "passing-neptune-cluster"
  engine                              = "neptune"
  backup_retention_period             = 5
  preferred_backup_window             = "07:00-09:00"
  skip_final_snapshot                 = true
  iam_database_authentication_enabled = true

  # Audit logging is enabled
  enable_cloudwatch_logs_exports = ["audit"]
}
