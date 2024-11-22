provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "pass-neptune-cluster"
  engine = "neptune"
  
  # Enable audit logs for CloudWatch
  enable_cloudwatch_logs_exports = ["audit"]

  tags = {
    Environment = "production"
  }
}
