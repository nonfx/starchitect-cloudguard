provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "fail-neptune-cluster"
  engine = "neptune"
  backup_retention_period = 5  # Less than minimum required
  skip_final_snapshot = true

  tags = {
    Environment = "test"
  }
}
