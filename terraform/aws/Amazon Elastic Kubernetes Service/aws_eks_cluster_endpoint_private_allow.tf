provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create VPC for EKS
resource "aws_vpc" "pass_vpc" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "pass-eks-vpc"
  }
}

# Create subnet for EKS
resource "aws_subnet" "pass_subnet" {
  provider = aws.pass_aws
  vpc_id = aws_vpc.pass_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "pass-eks-subnet"
  }
}

# Create IAM role for EKS
resource "aws_iam_role" "pass_eks_role" {
  provider = aws.pass_aws
  name = "pass-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

# Create EKS cluster with private endpoint access only
resource "aws_eks_cluster" "pass_cluster" {
  provider = aws.pass_aws
  name = "pass-cluster"
  role_arn = aws_iam_role.pass_eks_role.arn

  vpc_config {
    subnet_ids = [aws_subnet.pass_subnet.id]
    endpoint_private_access = true
    endpoint_public_access = false
  }
}