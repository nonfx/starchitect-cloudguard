provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_rds_cluster" "passing_example" {
  provider                            = aws.passing
  engine                              = "mysql"
  iam_database_authentication_enabled = true
}
