provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_dax_cluster" "fail_test" {
  provider = aws.fail_aws
  cluster_name = "fail-dax-cluster"
  node_type    = "dax.t3.small"
  replication_factor = 1

  iam_role_arn = "arn:aws:iam::123456789012:role/DAXServiceRole"

  # No server side encryption configuration
}
