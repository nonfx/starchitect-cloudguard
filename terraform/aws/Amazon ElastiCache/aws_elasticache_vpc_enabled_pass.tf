provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_vpc" "passing_example" {
  provider   = aws.passing
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "tf-test"
  }
}

resource "aws_subnet" "passing_example" {
  provider          = aws.passing
  vpc_id            = aws_vpc.passing_example.id
  cidr_block        = "10.0.0.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "tf-test"
  }
}

resource "aws_elasticache_subnet_group" "passing_example" {
  provider   = aws.passing
  name       = "tf-test-cache-subnet"
  subnet_ids = [aws_subnet.passing_example.id]
}

resource "aws_elasticache_cluster" "passing_example" {
  provider            = aws.passing
  cluster_id          = "passing-cluster"
  engine              = "redis"
  node_type           = "cache.t3.micro"
  num_cache_nodes     = 1
  parameter_group_name = "default.redis6.x"
  port                = 6379
  subnet_group_name   = aws_elasticache_subnet_group.passing_example.name
}
