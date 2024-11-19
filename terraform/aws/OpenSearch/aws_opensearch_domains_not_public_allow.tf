provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create VPC resources
resource "aws_vpc" "pass_test" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "pass-test-vpc"
  }
}

resource "aws_subnet" "pass_test_1" {
  provider = aws.pass_aws
  vpc_id = aws_vpc.pass_test.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "pass-test-subnet-1"
  }
}

resource "aws_subnet" "pass_test_2" {
  provider = aws.pass_aws
  vpc_id = aws_vpc.pass_test.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "us-west-2b"

  tags = {
    Name = "pass-test-subnet-2"
  }
}

# Create OpenSearch domain with VPC configuration
resource "aws_opensearch_domain" "pass_test" {
  provider = aws.pass_aws
  domain_name = "pass-test-domain"

  cluster_config {
    instance_type = "t3.small.search"
    instance_count = 1
  }

  vpc_options {
    subnet_ids = [
      aws_subnet.pass_test_1.id,
      aws_subnet.pass_test_2.id
    ]
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  encrypt_at_rest {
    enabled = true
  }

  tags = {
    Environment = "production"
  }
}