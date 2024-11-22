provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "pass_test_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "neptune-cluster-pass"
  engine = "neptune"
  copy_tags_to_snapshot = true
  
  tags = {
    Environment = "Production"
    Project = "TestProject"
  }
}