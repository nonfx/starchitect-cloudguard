provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "neptune-cluster-fail"
  engine = "neptune"
  storage_encrypted = false

  tags = {
    Environment = "test"
  }
}
