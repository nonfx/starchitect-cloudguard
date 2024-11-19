provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create EKS cluster with audit logging enabled
resource "aws_eks_cluster" "pass_cluster" {
  provider = aws.pass_aws
  name     = "pass-cluster"
  role_arn = aws_iam_role.pass_cluster.arn

  vpc_config {
    subnet_ids = ["subnet-12345678", "subnet-87654321"]
  }

  # Enable audit logging along with other log types
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [aws_iam_role_policy_attachment.pass_cluster_policy]
}

# Required IAM role for EKS cluster
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

# Attach required policy to IAM role
resource "aws_iam_role_policy_attachment" "pass_cluster_policy" {
  provider = aws.pass_aws
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.pass_cluster.name
}