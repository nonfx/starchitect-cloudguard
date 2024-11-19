provider "aws" {
  region = "us-west-2"
}

resource "aws_kms_key" "memorydb" {
  description             = "KMS key for MemoryDB cluster encryption"
  deletion_window_in_days = 7
}

resource "aws_memorydb_cluster" "example" {
  cluster_name = "my-cluster"
  node_type    = "db.t4g.small"
  num_shards   = 1

  tls_enabled = true  # Encryption in transit enabled
}
