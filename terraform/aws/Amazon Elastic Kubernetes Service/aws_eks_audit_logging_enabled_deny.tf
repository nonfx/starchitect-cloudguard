provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create EKS cluster without audit logging
resource "aws_eks_cluster" "fail_cluster" {
  provider = aws.fail_aws
  name     = "fail-cluster"
  role_arn = aws_iam_role.fail_cluster.arn

  vpc_config {
    subnet_ids = ["subnet-12345678", "subnet-87654321"]
  }

  # No audit logging enabled
  enabled_cluster_log_types = ["api", "controllerManager"]

  depends_on = [aws_iam_role_policy_attachment.fail_cluster_policy]
}

# Required IAM role for EKS cluster
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

# Attach required policy to IAM role
resource "aws_iam_role_policy_attachment" "fail_cluster_policy" {
  provider = aws.fail_aws
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.fail_cluster.name
}