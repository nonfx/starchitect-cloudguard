provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "pass-neptune-cluster"
  engine = "neptune"
  backup_retention_period = 7  # Meets minimum requirement
  skip_final_snapshot = true

  tags = {
    Environment = "production"
  }
}
