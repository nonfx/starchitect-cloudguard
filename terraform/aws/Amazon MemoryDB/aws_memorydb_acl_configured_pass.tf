provider "aws" {
  region = "us-west-2"
}

resource "aws_memorydb_acl" "example_acl" {
  name       = "example-acl"
  user_names = [aws_memorydb_user.example_user.id]
}

resource "aws_memorydb_user" "example_user" {
  user_name     = "example-user"
  access_string = "on ~app:* ~cache:* &app:* +@read +@string +@list -@admin"
  authentication_mode {
    type      = "password"
    passwords = ["YourStrongPasswordHere"]
  }
}

resource "aws_memorydb_subnet_group" "example_subnet_group" {
  name       = "example-subnet-group"
  subnet_ids = ["subnet-12345678", "subnet-87654321"]
}

resource "aws_memorydb_cluster" "example_cluster" {
  acl_name                 = aws_memorydb_acl.example_acl.id
  name                     = "example-cluster"
  node_type                = "db.t4g.small"
  num_shards               = 2
  num_replicas_per_shard   = 1
  subnet_group_name        = aws_memorydb_subnet_group.example_subnet_group.id
  security_group_ids       = ["sg-12345678"]
  snapshot_retention_limit = 7
  port                     = 6379
  tags = {
    Environment = "Production"
    Project     = "MemoryDB Example"
  }
}
