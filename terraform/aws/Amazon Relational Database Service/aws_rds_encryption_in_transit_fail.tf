provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_rds_cluster" "failing_example" {
  provider = aws.failing
  engine   = "mysql"
  # Missing iam_database_authentication_enabled
}
