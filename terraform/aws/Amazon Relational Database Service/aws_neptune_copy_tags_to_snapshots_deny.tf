provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "fail_test_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "neptune-cluster-fail"
  engine = "neptune"
  copy_tags_to_snapshot = false
  
  tags = {
    Environment = "Production"
    Project = "TestProject"
  }
}