provider "aws" {
  region = "us-west-2"
}

resource "aws_kms_key" "neptune" {
  description             = "KMS key for Neptune cluster encryption"
  deletion_window_in_days = 7
}

resource "aws_neptune_cluster" "example" {
  cluster_identifier  = "neptune-cluster-demo"
  engine              = "neptune"
  engine_version      = "1.2.0.0"
  availability_zones  = ["us-west-2a", "us-west-2b", "us-west-2c"]
  skip_final_snapshot = true
  storage_encrypted   = true
  kms_key_arn         = aws_kms_key.neptune.arn
}
