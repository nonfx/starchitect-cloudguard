provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_neptune_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "neptune-cluster-pass"
  engine = "neptune"
  storage_encrypted = true
  kms_key_arn = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

  tags = {
    Environment = "production"
  }
}
