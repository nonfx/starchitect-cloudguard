provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "passing_example" {
  provider                          = aws.passing
  cluster_identifier                = "passing-neptune-cluster"
  engine                            = "neptune"
  backup_retention_period           = 5
  preferred_backup_window           = "07:00-09:00"
  skip_final_snapshot               = true
  iam_database_authentication_enabled = true
  apply_immediately                 = true
}
