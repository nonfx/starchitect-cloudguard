provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_eks_cluster" "fail_cluster" {
  provider = aws.fail_aws
  name     = "fail-cluster"
  role_arn = aws_iam_role.fail_cluster.arn

  vpc_config {
    subnet_ids = ["subnet-12345678", "subnet-87654321"]
  }

  # No encryption configuration specified
}

resource "aws_iam_role" "fail_cluster" {
  provider = aws.fail_aws
  name = "fail-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })
}