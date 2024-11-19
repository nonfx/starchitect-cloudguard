provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_kms_key" "pass_eks" {
  provider = aws.pass_aws
  description = "EKS Secret Encryption Key"
  enable_key_rotation = true
}

resource "aws_eks_cluster" "pass_cluster" {
  provider = aws.pass_aws
  name     = "pass-cluster"
  role_arn = aws_iam_role.pass_cluster.arn

  vpc_config {
    subnet_ids = ["subnet-12345678", "subnet-87654321"]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.pass_eks.arn
    }
    resources = ["secrets"]
  }
}

resource "aws_iam_role" "pass_cluster" {
  provider = aws.pass_aws
  name = "pass-eks-cluster-role"

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