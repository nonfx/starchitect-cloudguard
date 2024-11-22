provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_dax_cluster" "pass_test" {
  provider = aws.pass_aws
  cluster_name = "pass-dax-cluster"
  node_type    = "dax.t3.small"
  replication_factor = 1

  iam_role_arn = "arn:aws:iam::123456789012:role/DAXServiceRole"

  server_side_encryption {
    enabled = true
  }

  tags = {
    Environment = "production"
    Service     = "dax"
  }
}
