provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create VPC for EKS
resource "aws_vpc" "fail_vpc" {
  provider = aws.fail_aws
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "fail-eks-vpc"
  }
}

# Create subnet for EKS
resource "aws_subnet" "fail_subnet" {
  provider = aws.fail_aws
  vpc_id = aws_vpc.fail_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "fail-eks-subnet"
  }
}

# Create IAM role for EKS
resource "aws_iam_role" "fail_eks_role" {
  provider = aws.fail_aws
  name = "fail-eks-cluster-role"

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

# Create EKS cluster with public endpoint access
resource "aws_eks_cluster" "fail_cluster" {
  provider = aws.fail_aws
  name = "fail-cluster"
  role_arn = aws_iam_role.fail_eks_role.arn

  vpc_config {
    subnet_ids = [aws_subnet.fail_subnet.id]
    endpoint_private_access = false
    endpoint_public_access = true
  }
}