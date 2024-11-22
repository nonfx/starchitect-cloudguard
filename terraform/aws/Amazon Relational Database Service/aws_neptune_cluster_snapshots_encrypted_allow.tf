provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create an encrypted Neptune cluster with KMS key
resource "aws_neptune_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "pass-neptune-cluster"
  engine = "neptune"
  storage_encrypted = true
  kms_key_arn = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}

# Create an encrypted snapshot of the Neptune cluster
resource "aws_neptune_cluster_snapshot" "pass_snapshot" {
  provider = aws.pass_aws
  db_cluster_identifier = aws_neptune_cluster.pass_cluster.id
  db_cluster_snapshot_identifier = "pass-snapshot"
  storage_encrypted = true
}
