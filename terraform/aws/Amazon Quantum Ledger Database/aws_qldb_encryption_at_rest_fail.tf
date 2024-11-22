provider "aws" {
  region = "us-west-2"
}

resource "aws_qldb_ledger" "failing_ledger" {
  name = "failing-ledger"
  permissions_mode = "ALLOW_ALL"
  deletion_protection = false

  # No KMS key specified, which means default encryption is used
}
