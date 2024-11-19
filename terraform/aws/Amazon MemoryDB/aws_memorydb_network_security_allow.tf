provider "aws" {
  region = "us-west-2"
}

resource "aws_vpc" "example_vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "example_subnet" {
  vpc_id     = aws_vpc.example_vpc.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_security_group" "example_sg" {
  vpc_id = aws_vpc.example_vpc.id
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_memorydb_subnet_group" "example_subnet_group" {
  name       = "example-subnet-group"
  subnet_ids = [aws_subnet.example_subnet.id]
}

resource "aws_memorydb_cluster" "passing_cluster" {
  acl_name                 = "open-access"
  name                     = "my-cluster"
  node_type                = "db.t4g.small"
  num_shards               = 2
  snapshot_retention_limit = 7
  subnet_group_name        = aws_memorydb_subnet_group.example_subnet_group.name
  security_group_ids       = [aws_security_group.example_sg.id]

  num_replicas_per_shard   = 1
}
