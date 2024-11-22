provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "fail-neptune-cluster"
  engine = "neptune"
  
  # Audit logs not enabled for CloudWatch
  enable_cloudwatch_logs_exports = []

  tags = {
    Environment = "test"
  }
}
