provider "aws" {
  region = "us-west-2"
}

resource "aws_docdb_cluster" "example_fail" {
  cluster_identifier      = "my-docdb-cluster"
  engine                  = "docdb"
  master_username         = "foo"
  master_password         = "mustbeeightchars"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true

  # Encryption in transit is not enabled
  storage_encrypted       = false
}
