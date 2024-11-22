provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_ecs_cluster" "pass_cluster" {
  provider = aws.pass_aws
  name = "pass-test-cluster"

  # Enable Container Insights
  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Environment = "production"
    Monitoring = "enabled"
  }
}
