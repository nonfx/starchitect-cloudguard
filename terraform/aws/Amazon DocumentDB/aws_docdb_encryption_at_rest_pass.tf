provider "aws" {
  region = "us-west-2"
}

resource "aws_kms_key" "docdb" {
  description             = "KMS key for DocumentDB cluster encryption"
  deletion_window_in_days = 7
}

resource "aws_docdb_cluster" "example" {
  cluster_identifier      = "my-docdb-cluster"
  engine                  = "docdb"
  master_username         = "foo"
  master_password         = "mustbeeightchars"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.docdb.arn
}
