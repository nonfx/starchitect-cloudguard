provider "aws" {
  region = "us-west-2"
}

resource "aws_memorydb_cluster" "failing_cluster" {
  acl_name                 = "open-access"
  name                     = "my-cluster"
  node_type                = "db.t4g.small"
  num_shards               = 2
  snapshot_retention_limit = 7
  subnet_group_name      = ""
  security_group_ids     = []
}
