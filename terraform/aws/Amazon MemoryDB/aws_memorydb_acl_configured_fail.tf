provider "aws" {
  region = "us-west-2"
}

resource "aws_memorydb_user" "fail_user" {
  user_name     = "fail-user"
  access_string = "on ~* &* +@all"
  authentication_mode {
    type      = "password"
    passwords = []
  }
}

resource "aws_memorydb_acl" "fail_acl" {
  name       = "fail-acl"
  user_names = [aws_memorydb_user.fail_user.id]
}

resource "aws_memorydb_subnet_group" "fail_subnet_group" {
  name       = "fail-subnet-group"
  subnet_ids = ["subnet-12345678", "subnet-87654321"]
}

resource "aws_memorydb_cluster" "fail_cluster" {
  acl_name                 = aws_memorydb_acl.fail_acl.id
  name                     = "fail-cluster"
  node_type                = "db.t4g.small"
  num_shards               = 2
  num_replicas_per_shard   = 1
  subnet_group_name        = aws_memorydb_subnet_group.fail_subnet_group.id
  security_group_ids       = ["sg-12345678"]
  snapshot_retention_limit = 7
  port                     = 6379
  tags = {
    Environment = "Production"
    Project     = "MemoryDB Example"
  }
}
