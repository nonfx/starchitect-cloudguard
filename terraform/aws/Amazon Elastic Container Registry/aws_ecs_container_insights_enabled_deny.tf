provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_ecs_cluster" "fail_cluster" {
  provider = aws.fail_aws
  name = "fail-test-cluster"

  # Container Insights not enabled
  setting {
    name  = "containerInsights"
    value = "disabled"
  }

  tags = {
    Environment = "test"
  }
}
