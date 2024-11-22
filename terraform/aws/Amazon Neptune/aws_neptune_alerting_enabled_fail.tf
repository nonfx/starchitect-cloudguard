provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "failing_example" {
  provider                  = aws.failing
  cluster_identifier        = "failing-neptune-cluster"
  engine                    = "neptune"
  backup_retention_period   = 5
  preferred_backup_window   = "07:00-09:00"
  skip_final_snapshot       = true
  iam_database_authentication_enabled = true
  apply_immediately         = true
  
  enable_cloudwatch_logs_exports = ["audit"]
}
