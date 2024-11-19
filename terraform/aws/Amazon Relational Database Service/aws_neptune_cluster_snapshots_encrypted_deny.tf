provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create an unencrypted Neptune cluster
resource "aws_neptune_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "fail-neptune-cluster"
  engine = "neptune"
  storage_encrypted = false
}

# Create an unencrypted snapshot of the Neptune cluster
resource "aws_neptune_cluster_snapshot" "fail_snapshot" {
  provider = aws.fail_aws
  db_cluster_identifier = aws_neptune_cluster.fail_cluster.id
  db_cluster_snapshot_identifier = "fail-snapshot"
  storage_encrypted = false
}
