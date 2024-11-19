provider "aws" {
  region = "us-west-2"
}

resource "aws_memorydb_cluster" "example" {
  cluster_name = "my-cluster"
  node_type    = "db.t4g.small"
  num_shards   = 1
  tls_enabled  = false  # Encryption in transit disabled
}
