provider "aws" {
  region = "us-west-2"
}

resource "aws_kms_key" "qldb_key" {
  description = "KMS key for QLDB encryption"
  enable_key_rotation = true
}

resource "aws_qldb_ledger" "passing_ledger" {
  name = "passing-ledger"
  permissions_mode = "ALLOW_ALL"
  deletion_protection = true

  # Specify the KMS key for encryption at rest
  kms_key = aws_kms_key.qldb_key.arn
}
